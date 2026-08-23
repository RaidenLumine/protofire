//! src/arch/aarch64/fdt.rs
//! Minimal Flattened Device Tree parser for AArch64 platform discovery.
//!
//! QEMU passes a device tree blob (DTB) address in x0 on boot; this module
//! parses just enough of the FDT to discover the GIC, UART, VirtIO MMIO, and
//! timer addresses.  If parsing fails (malformed FDT, unexpected platform),
//! all fields are `None` and callers fall back to hardcoded QEMU `virt`
//! constants.
//!
//! ## FDT layout (simplified)
//!
//! ```text
//! +------------------+
//! | Header (40 bytes)|  magic, totalsize, offsets to struct/strings blocks
//! +------------------+
//! | Memory reserve   |  list of (addr, size) pairs, terminated by zeros
//! | map              |
//! +------------------+
//! | Structure block  |  sequence of BEGIN_NODE / PROP / END_NODE / END tokens
//! +------------------+
//! | Strings block    |  concatenated NUL-terminated property name strings
//! +------------------+
//! ```
//!
//! All multi-byte integers are big-endian (FDT is an external data format).

use core::ptr::read_unaligned;

use crate::kernel::sync::SpinLock;

// ---------------------------------------------------------------------------
// FDT header offsets and magic
// ---------------------------------------------------------------------------

const FDT_MAGIC: u32 = 0xd00d_feed;

const OFF_MAGIC: usize = 0;
const OFF_TOTALSIZE: usize = 4;
const OFF_OFF_DT_STRUCT: usize = 8;
const OFF_OFF_DT_STRINGS: usize = 12;
const OFF_VERSION: usize = 20;
const OFF_LAST_COMP_VERSION: usize = 24;

// ---------------------------------------------------------------------------
// Structure block tokens
// ---------------------------------------------------------------------------

const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_END: u32 = 0x0000_0009;

// ---------------------------------------------------------------------------
// Compatible strings we match against
// ---------------------------------------------------------------------------

const COMPAT_GIC_400: &str = "arm,gic-400";
const COMPAT_GIC_CORTEX_A15: &str = "arm,cortex-a15-gic";
const COMPAT_GIC_V3: &str = "arm,gic-v3";
const COMPAT_GIC_V3_ITS: &str = "arm,gic-v3-its";
const COMPAT_PL011: &str = "arm,pl011";
const COMPAT_VIRTIO_MMIO: &str = "virtio,mmio";
const COMPAT_PL031: &str = "arm,pl031";
// RISC-V platform devices.
const COMPAT_RISCV_PLIC0: &str = "riscv,plic0";
const COMPAT_NS16550A: &str = "ns16550a";
const COMPAT_GOLDFISH_RTC: &str = "google,goldfish-rtc";
const COMPAT_PCI_HOST_ECAM: &str = "pci-host-ecam-generic";

// ---------------------------------------------------------------------------
// PlatformInfo
// ---------------------------------------------------------------------------

/// Hardware addresses discovered from the FDT.
///
/// Every field is `Option` — if the FDT does not describe a device we
/// recognise, the field stays `None` and the caller falls back to hardcoded
/// QEMU `virt` constants.
#[derive(Debug, Clone, Copy)]
pub struct PlatformInfo {
    pub gicd_base: Option<usize>,
    pub gicc_base: Option<usize>,
    /// GICv3 redistributor base address (from FDT GICv3 node, second reg entry).
    pub gicr_base: Option<usize>,
    /// GICv3 ITS (Interrupt Translation Service) base address.
    pub its_base: Option<usize>,
    /// True if the platform uses GICv3 (detected from compatible "arm,gic-v3").
    pub gicv3_detected: bool,
    pub uart_base: Option<usize>,
    pub virtio_mmio_base: Option<usize>,
    pub virtio_mmio_stride: Option<usize>,
    pub virtio_mmio_count: Option<usize>,
    pub timer_frequency: Option<u64>,
    pub rtc_base: Option<usize>,
    /// RISC-V PLIC (Platform-Level Interrupt Controller) base address.
    pub plic_base: Option<usize>,
    /// PCIe ECAM (MMCONFIG) base address, discovered from
    /// `compatible = "pci-host-ecam-generic"`.
    pub ecam_base: Option<usize>,
    /// First PCI bus covered by the ECAM region.
    pub ecam_start_bus: Option<u8>,
    /// Last PCI bus covered by the ECAM region (inclusive).
    pub ecam_end_bus: Option<u8>,
    /// Whether the RISC-V Sstc (Supervisor Timer Compare) extension is
    /// available, detected from `riscv,isa` in a CPU node.
    pub has_sstc: bool,
    /// Total number of CPU cores discovered from FDT `/cpus` node.
    pub cpu_count: u32,
    /// Physical memory base address (from `/memory` node `reg` property).
    pub memory_base: Option<usize>,
    /// Physical memory size in bytes (from `/memory` node `reg` property).
    pub memory_size: Option<usize>,
    /// Minimum CPU frequency in Hz, from the OPP table referenced by a CPU
    /// node (`operating-points-v2`) or a legacy `operating-points` tuple.
    pub cpu_freq_min_hz: Option<u64>,
    /// Maximum CPU frequency in Hz, from the same OPP sources as
    /// `cpu_freq_min_hz`.
    pub cpu_freq_max_hz: Option<u64>,
}

impl PlatformInfo {
    /// An empty platform description (all fields `None`).
    pub const fn empty() -> Self {
        Self {
            gicd_base: None,
            gicc_base: None,
            gicr_base: None,
            its_base: None,
            gicv3_detected: false,
            uart_base: None,
            virtio_mmio_base: None,
            virtio_mmio_stride: None,
            virtio_mmio_count: None,
            timer_frequency: None,
            rtc_base: None,
            plic_base: None,
            ecam_base: None,
            ecam_start_bus: None,
            ecam_end_bus: None,
            has_sstc: false,
            cpu_count: 0,
            memory_base: None,
            memory_size: None,
            cpu_freq_min_hz: None,
            cpu_freq_max_hz: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Global platform-info singleton
// ---------------------------------------------------------------------------

/// Platform information populated early during boot by parsing the FDT.
///
/// On aarch64 bare-metal this is filled before the interrupt controller,
/// serial, and timer are initialised.  If the FDT is absent or malformed
/// all fields remain `None` and the subsystems fall back to hardcoded
/// QEMU `virt` constants.
static PLATFORM_INFO: SpinLock<PlatformInfo> = SpinLock::new(PlatformInfo::empty());

/// Store platform information discovered from the FDT (or empty on failure).
///
/// Called once during early boot, before any device initialisation.
pub fn store_platform_info(info: PlatformInfo) {
    *PLATFORM_INFO.lock() = info;
}

/// Return a copy of the platform information.
///
/// Safe to call at any time after `store_platform_info`; returns the
/// empty default if not yet populated (host-mode tests).
pub fn platform_info() -> PlatformInfo {
    *PLATFORM_INFO.lock()
}

/// Return the number of CPU cores discovered from the FDT `/cpus` node.
///
/// Returns 0 if no FDT was parsed or no CPU nodes were found.
pub fn cpu_count() -> u32 {
    platform_info().cpu_count
}

// ---------------------------------------------------------------------------
// FDT NUMA info (fixed-size, no heap required)
// ---------------------------------------------------------------------------

/// Fixed-size container for NUMA data discovered during FDT parsing.
///
/// Uses arrays instead of `Vec` because the heap is not yet available when
/// the FDT is parsed (pre-`Kernel::init`).  Later,
/// [`build_fdt_numa_topology`] converts this into a heap-allocated
/// [`crate::kernel::topology::Topology`].
#[derive(Debug, Clone, Copy)]
pub struct FdtNumaInfo {
    /// (logical_cpu_id, node_id) pairs.  Unused entries have node_id = 0xFF.
    cpu_to_node: [(u32, u8); 16],
    /// Number of valid entries in `cpu_to_node`.
    cpu_count: u32,
    /// (node_id, base, end) memory ranges.
    memory_ranges: [(u8, u64, u64); 16],
    /// Number of valid entries in `memory_ranges`.
    memory_count: u32,
    /// Flat distance matrix, max 8x8 = 64 entries (index = i * 8 + j).
    distance_matrix: [u8; 64],
    /// Number of nodes represented in `distance_matrix`.
    distance_node_count: u32,
}

impl FdtNumaInfo {
    /// An empty NUMA description (no NUMA data).
    pub const fn empty() -> Self {
        Self {
            cpu_to_node: [(0, 0xFF); 16],
            cpu_count: 0,
            memory_ranges: [(0, 0, 0); 16],
            memory_count: 0,
            distance_matrix: [0; 64],
            distance_node_count: 0,
        }
    }

    /// Record a CPU → node mapping.
    fn add_cpu(&mut self, cpu_id: u32, node_id: u8) {
        let idx = self.cpu_count as usize;
        if idx < self.cpu_to_node.len() {
            self.cpu_to_node[idx] = (cpu_id, node_id);
            self.cpu_count = (idx + 1) as u32;
        }
    }

    /// Record a memory range belonging to a node.
    fn add_memory(&mut self, node_id: u8, base: u64, end: u64) {
        let idx = self.memory_count as usize;
        if idx < self.memory_ranges.len() {
            self.memory_ranges[idx] = (node_id, base, end);
            self.memory_count = (idx + 1) as u32;
        }
    }

    /// Set a single distance matrix entry.
    fn set_distance(&mut self, local: u32, remote: u32, distance: u8) {
        const MAX_DIST_NODES: usize = 8;
        let i = local as usize;
        let j = remote as usize;
        if i < MAX_DIST_NODES && j < MAX_DIST_NODES {
            self.distance_matrix[i * MAX_DIST_NODES + j] = distance;
            if local + 1 > self.distance_node_count {
                self.distance_node_count = local + 1;
            }
            if remote + 1 > self.distance_node_count {
                self.distance_node_count = remote + 1;
            }
        }
    }
}

/// Stores the FDT NUMA info populated during [`parse_fdt`].
static FDT_NUMA_INFO: SpinLock<FdtNumaInfo> = SpinLock::new(FdtNumaInfo::empty());

/// Store NUMA information discovered from the FDT (or empty on failure).
pub fn store_fdt_numa_info(info: FdtNumaInfo) {
    *FDT_NUMA_INFO.lock() = info;
}

/// Return a copy of the FDT NUMA information.
pub fn fdt_numa_info() -> FdtNumaInfo {
    *FDT_NUMA_INFO.lock()
}

/// Build a heap-allocated [`Topology`] from the FDT NUMA data, if any.
///
/// Returns `None` when no NUMA data was found in the FDT (the caller should
/// fall back to a single-node topology).
pub fn build_fdt_numa_topology() -> Option<crate::kernel::topology::Topology> {
    use crate::kernel::topology::{NodeId, NumaNode, MAX_NUMA_NODES};

    let numa = fdt_numa_info();
    if numa.cpu_count == 0 && numa.memory_count == 0 {
        return None;
    }

    // ── Collect unique node IDs from CPU and memory entries ──
    let mut node_ids: [NodeId; MAX_NUMA_NODES] = [0xFF; MAX_NUMA_NODES];
    let mut unique_count = 0usize;

    for i in 0..numa.cpu_count as usize {
        let (_cpu_id, nid) = numa.cpu_to_node[i];
        if nid != 0xFF {
            let mut found = false;
            for &existing in node_ids.iter().take(unique_count) {
                if existing == nid {
                    found = true;
                    break;
                }
            }
            if !found && unique_count < MAX_NUMA_NODES {
                node_ids[unique_count] = nid;
                unique_count += 1;
            }
        }
    }
    for i in 0..numa.memory_count as usize {
        let (nid, _base, _end) = numa.memory_ranges[i];
        let mut found = false;
        for &existing in node_ids.iter().take(unique_count) {
            if existing == nid {
                found = true;
                break;
            }
        }
        if !found && unique_count < MAX_NUMA_NODES {
            node_ids[unique_count] = nid;
            unique_count += 1;
        }
    }

    // If no nodes discovered, return a single-node topology.
    if unique_count == 0 {
        return None;
    }

    // ── Build NumaNode list ──
    let mut nodes: alloc::vec::Vec<NumaNode> = alloc::vec::Vec::with_capacity(unique_count);
    for &nid in node_ids[..unique_count].iter() {
        nodes.push(NumaNode {
            id: nid,
            cpu_ids: alloc::vec::Vec::new(),
            memory_ranges: alloc::vec::Vec::new(),
        });
    }

    // Assign CPUs to nodes.
    for i in 0..numa.cpu_count as usize {
        let (cpu_id, nid) = numa.cpu_to_node[i];
        if nid != 0xFF {
            for node in &mut nodes {
                if node.id == nid {
                    node.cpu_ids.push(cpu_id);
                    break;
                }
            }
        }
    }

    // Assign memory ranges to nodes.
    for i in 0..numa.memory_count as usize {
        let (nid, base, end) = numa.memory_ranges[i];
        for node in &mut nodes {
            if node.id == nid {
                node.memory_ranges.push((base, end));
                break;
            }
        }
    }

    // ── Build cpu_to_node Vec ──
    // Determine the maximum CPU ID to size the Vec.
    let max_cpu_id = numa
        .cpu_to_node
        .iter()
        .take(numa.cpu_count as usize)
        .map(|&(cid, _)| cid)
        .max()
        .unwrap_or(0) as usize;
    let mut cpu_to_node: alloc::vec::Vec<NodeId> = alloc::vec![0u8; (max_cpu_id + 1).max(1)];
    for i in 0..numa.cpu_count as usize {
        let (cpu_id, nid) = numa.cpu_to_node[i];
        if nid != 0xFF && (cpu_id as usize) < cpu_to_node.len() {
            cpu_to_node[cpu_id as usize] = nid;
        }
    }

    // ── Distance matrix ──
    let dn = numa.distance_node_count as usize;
    let distance_matrix = if dn > 0 {
        let mut mat: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::with_capacity(dn);
        for i in 0..dn {
            let mut row: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(dn);
            for j in 0..dn {
                row.push(numa.distance_matrix[i * 8 + j]);
            }
            mat.push(row);
        }
        mat
    } else {
        alloc::vec::Vec::new()
    };

    Some(crate::kernel::topology::Topology {
        nodes,
        cpu_to_node,
        distance_matrix,
    })
}

// ---------------------------------------------------------------------------
// Raw FDT access helpers
// ---------------------------------------------------------------------------

/// Read a big-endian u32 from the FDT blob at `base + offset`.
///
/// # Safety
///
/// `base` must point to a valid FDT blob of at least `offset + 4` bytes.
/// The read is unaligned — FDT fields may be at any offset.
unsafe fn read_u32_be(base: *const u8, offset: usize) -> u32 {
    let raw = unsafe { read_unaligned((base.add(offset)) as *const u32) };
    u32::from_be(raw)
}

/// Read a null-terminated string from the FDT strings block.
///
/// Returns `None` if the offset is out of bounds or no NUL terminator is
/// found within `max_len` bytes.
///
/// # Safety
///
/// `strings_base` must point to valid memory.
unsafe fn read_str(
    strings_base: *const u8,
    strings_size: usize,
    offset: usize,
) -> Option<&'static str> {
    if offset >= strings_size {
        return None;
    }

    let ptr = unsafe { strings_base.add(offset) };
    let remaining = strings_size - offset;
    let len = (0..remaining).find(|&i| unsafe { *ptr.add(i) } == 0)?;

    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(slice).ok()
}

// ---------------------------------------------------------------------------
// FDT parsing
// ---------------------------------------------------------------------------

/// Parse the flattened device tree at `fdt_addr` and return discovered
/// platform information.
///
/// If the FDT is malformed, missing, or describes an unrecognised platform,
/// the returned `PlatformInfo` will have all fields set to `None` — the
/// caller should fall back to hardcoded constants.
pub fn parse_fdt(fdt_addr: usize) -> PlatformInfo {
    if fdt_addr == 0 {
        return PlatformInfo::empty();
    }

    let base = fdt_addr as *const u8;

    // Validate magic and version in the header.
    let magic = unsafe { read_u32_be(base, OFF_MAGIC) };
    if magic != FDT_MAGIC {
        return PlatformInfo::empty();
    }

    let version = unsafe { read_u32_be(base, OFF_VERSION) };
    let last_comp_version = unsafe { read_u32_be(base, OFF_LAST_COMP_VERSION) };
    // We support FDT v17 (the current standard version).
    if version < 17 || last_comp_version > 17 {
        return PlatformInfo::empty();
    }

    let totalsize = unsafe { read_u32_be(base, OFF_TOTALSIZE) } as usize;
    let off_dt_struct = unsafe { read_u32_be(base, OFF_OFF_DT_STRUCT) } as usize;
    let off_dt_strings = unsafe { read_u32_be(base, OFF_OFF_DT_STRINGS) } as usize;

    // totalsize includes the header; strings block size is totalsize - off_dt_strings.
    if off_dt_struct >= totalsize || off_dt_strings >= totalsize || off_dt_struct >= off_dt_strings
    {
        return PlatformInfo::empty();
    }

    let strings_base = unsafe { base.add(off_dt_strings) };
    let strings_size = totalsize - off_dt_strings;

    let struct_ptr = unsafe { base.add(off_dt_struct) };
    let struct_end = unsafe { base.add(off_dt_strings) }; // struct block ends where strings begin

    // Temporary accumulators during tree walk.
    let mut info = PlatformInfo::empty();
    let mut virtio_mmio_bases: [Option<usize>; 8] = [None; 8];
    let mut virtio_mmio_idx: usize = 0;
    // Track whether the current node is a PCI host bridge (for ECAM discovery).
    let mut current_is_pci_host: bool = false;
    let mut current_is_gicv3: bool = false;
    let mut current_is_its: bool = false;
    let mut current_is_memory_node: bool = false;
    // ── NUMA tracking ──────────────────────────────────────────────────
    let mut fdt_numa = FdtNumaInfo::empty();
    // Index of the current CPU node (-1 = not in a CPU node).
    let mut cpu_node_idx: isize = -1;
    let mut current_is_distance_map: bool = false;
    // NUMA node ID from the current memory node's `numa-node-id` property.
    let mut pending_memory_node_id: Option<u8> = None;
    // Temporarily stores the last memory reg parsed for the current node.
    let mut node_pending_memory_base: u64 = 0;
    let mut node_pending_memory_size: u64 = 0;
    let mut node_has_memory_reg: bool = false;

    // ── OPP (Operating Performance Points) CPU frequency tracking ──────
    // CPU frequency ranges discovered from device-tree OPP tables
    // (`operating-points-v2` phandles) and legacy `operating-points`
    // frequency/voltage tuples.
    let mut opp_tables: [(u32, u64, u64); 8] = [(0, 0, 0); 8]; // (phandle, min, max)
    let mut opp_table_count: usize = 0;
    let mut cpu_opp_phandles: [u32; 16] = [0; 16];
    let mut cpu_opp_count: usize = 0;
    let mut legacy_opp_min: u64 = u64::MAX;
    let mut legacy_opp_max: u64 = 0;
    let mut legacy_opp_found: bool = false;
    // Per-node state while walking the tree.
    let mut node_phandle: Option<u32> = None;
    let mut opp_table_active: bool = false;
    let mut opp_table_depth: usize = usize::MAX;
    let mut current_table_phandle: Option<u32> = None;
    let mut current_table_min: u64 = u64::MAX;
    let mut current_table_max: u64 = 0;
    let mut current_table_disabled: bool = false;
    let mut opp_node_hz: Option<u64> = None;
    let mut opp_node_disabled: bool = false;

    // We walk the structure block with a simple recursive-descent style,
    // tracking the current node path depth and the #address-cells / #size-cells
    // for the current node.  We reset cells when entering a new node and
    // inherit from parent otherwise.
    #[derive(Clone, Copy)]
    struct NodeCtx {
        address_cells: u32,
        size_cells: u32,
        _depth: usize,
    }

    let root_ctx = NodeCtx {
        // QEMU virt defaults for the root node on a 64-bit platform.
        address_cells: 2,
        size_cells: 2,
        _depth: 0,
    };

    let mut path: [NodeCtx; 16] = [root_ctx; 16];
    let mut current_depth: usize = 0;
    // Node classification per depth (0 = other, 1 = timer/cpu). Used to keep
    // the generic `clock-frequency` handler from mistaking a UART/APB clock
    // for the arch timer frequency (riscv64 virt's 16550 UART carries
    // clock-frequency = 3,686,400, which is not the timer rate).
    let mut node_kind: [u8; 16] = [0; 16];

    /// Advance `ptr` to the next 4-byte alignment boundary.
    fn align4(ptr: *const u8, base_ptr: *const u8) -> *const u8 {
        let offset = (ptr as usize).wrapping_sub(base_ptr as usize);
        let aligned = (offset + 3) & !3;
        unsafe { base_ptr.add(aligned) }
    }

    let mut ptr = struct_ptr;

    // Main structure-block loop.
    while ptr < struct_end {
        if ptr.wrapping_offset(4) > struct_end {
            break;
        }

        let token = unsafe { read_u32_be(ptr, 0) };
        ptr = unsafe { ptr.add(4) };

        match token {
            FDT_BEGIN_NODE => {
                // Node name: NUL-terminated string.
                let name_start = ptr;
                let mut name_len: usize = 0;
                while ptr < struct_end && unsafe { *ptr } != 0 {
                    ptr = unsafe { ptr.add(1) };
                    name_len += 1;
                }
                // Skip the NUL terminator.
                if ptr < struct_end {
                    ptr = unsafe { ptr.add(1) };
                }
                ptr = align4(ptr, base);

                let node_name = core::str::from_utf8(unsafe {
                    core::slice::from_raw_parts(name_start, name_len)
                })
                .unwrap_or("");

                // Count CPU nodes — they are children of the "/cpus" node.
                // At this point current_depth is the parent depth. A CPU node
                // is at depth 2 (root → cpus → cpu@N), so its parent depth is 2.
                if current_depth == 2 && node_name.starts_with("cpu") {
                    cpu_node_idx = info.cpu_count as isize; // before increment
                    info.cpu_count += 1;
                }

                // Detect /memory node at depth 1.
                if current_depth == 1 && node_name.starts_with("memory") {
                    current_is_memory_node = true;
                    node_has_memory_reg = false;
                    pending_memory_node_id = None;
                }

                // Detect /distance-map node at depth 1.
                if current_depth == 1 && node_name == "distance-map" {
                    current_is_distance_map = true;
                }

                current_depth += 1;
                if current_depth < path.len() {
                    // Inherit parent's cells. Path indices 0..=current_depth-1 are valid
                    // (0 is root, always valid), and we want to write at current_depth
                    // after inheriting — but actually current_depth is the new depth after
                    // increment, so path[current_depth - 1] is the parent.
                    path[current_depth] = path[current_depth - 1];
                    // Classify the current node so property handlers can tell a
                    // timer/CPU node (whose clock-frequency/timebase is the timer
                    // rate) apart from peripheral nodes like a 16550 UART.
                    node_kind[current_depth] = if node_name == "timer"
                        || node_name.starts_with("timer@")
                        || node_name.starts_with("cpu")
                    {
                        1
                    } else {
                        0
                    };
                }

                // Reset per-node OPP state; each node starts clean.
                node_phandle = None;
                opp_node_hz = None;
                opp_node_disabled = false;
            }

            FDT_END_NODE => {
                let was_depth = current_depth;
                current_depth = current_depth.saturating_sub(1);
                current_is_pci_host = false;
                current_is_gicv3 = false;
                current_is_its = false;
                current_is_memory_node = false;
                current_is_distance_map = false;
                cpu_node_idx = -1;
                pending_memory_node_id = None;
                node_has_memory_reg = false;

                // ── OPP finalization ──
                if opp_table_active && was_depth == opp_table_depth {
                    // Exiting the OPP table node itself: record the table.
                    if let Some(ph) = current_table_phandle {
                        if current_table_min <= current_table_max
                            && opp_table_count < opp_tables.len()
                        {
                            opp_tables[opp_table_count] =
                                (ph, current_table_min, current_table_max);
                            opp_table_count += 1;
                        }
                    }
                    opp_table_active = false;
                    opp_table_depth = usize::MAX;
                    current_table_phandle = None;
                    current_table_min = u64::MAX;
                    current_table_max = 0;
                    current_table_disabled = false;
                } else if opp_table_active && was_depth > opp_table_depth {
                    // Exiting an `opp-N` child node: commit its `opp-hz`.
                    if let Some(hz) = opp_node_hz {
                        if !current_table_disabled && !opp_node_disabled {
                            current_table_min = current_table_min.min(hz);
                            current_table_max = current_table_max.max(hz);
                        }
                    }
                }
                opp_node_hz = None;
                opp_node_disabled = false;
                // Nothing to skip — END_NODE has no payload.
            }

            FDT_PROP => {
                if ptr.wrapping_offset(8) > struct_end {
                    break;
                }

                let len = unsafe { read_u32_be(ptr, 0) } as usize;
                let nameoff = unsafe { read_u32_be(ptr, 4) } as usize;
                ptr = unsafe { ptr.add(8) };

                let prop_name = unsafe { read_str(strings_base, strings_size, nameoff) };

                // Advance past the property value.
                let value_ptr = ptr;
                let value_len = len;
                ptr = unsafe { ptr.add(len) };
                ptr = align4(ptr, base);

                // After advancing ptr we're safe to read the value.
                if value_len == 0 || value_ptr.wrapping_add(value_len) > struct_end {
                    continue;
                }

                let ctx = if current_depth < path.len() {
                    path[current_depth]
                } else {
                    root_ctx
                };

                // True when the current node is a timer or CPU node.  A generic
                // `clock-frequency` here is the timer/counter rate; on peripheral
                // nodes (serial UART, APB clocks) it is unrelated to the timer.
                let in_timer_or_cpu_node =
                    current_depth < node_kind.len() && node_kind[current_depth] != 0;

                match prop_name {
                    Some("#address-cells") => {
                        if value_len >= 4 && current_depth < path.len() {
                            path[current_depth].address_cells =
                                unsafe { read_u32_be(value_ptr, 0) };
                        }
                    }
                    Some("#size-cells") => {
                        if value_len >= 4 && current_depth < path.len() {
                            path[current_depth].size_cells = unsafe { read_u32_be(value_ptr, 0) };
                        }
                    }
                    Some("compatible") => {
                        let compatible = core::str::from_utf8(unsafe {
                            core::slice::from_raw_parts(value_ptr, value_len.min(128))
                        })
                        .unwrap_or("");

                        // Check compat strings that require reading the parent's `reg`.
                        if compatible.contains(COMPAT_GIC_400)
                            || compatible.contains(COMPAT_GIC_CORTEX_A15)
                        {
                            // GICv2 reg will be parsed from the parent node's reg property.
                        } else if compatible.contains(COMPAT_GIC_V3) {
                            current_is_gicv3 = true;
                            info.gicv3_detected = true;
                        } else if compatible.contains(COMPAT_GIC_V3_ITS) {
                            current_is_its = true;
                        } else if compatible.contains(COMPAT_PL011)
                            || compatible.contains(COMPAT_NS16550A)
                        {
                            // UART reg will be parsed from the parent node's reg property.
                        } else if compatible.contains(COMPAT_PL031)
                            || compatible.contains(COMPAT_GOLDFISH_RTC)
                        {
                            // RTC reg will be parsed from the parent node's reg property.
                        } else if compatible.contains(COMPAT_VIRTIO_MMIO) {
                            // VirtIO MMIO reg will be parsed from the parent node's reg property.
                        } else if compatible.contains(COMPAT_RISCV_PLIC0) {
                            // PLIC reg will be parsed from the parent node's reg property.
                        } else if compatible.contains(COMPAT_PCI_HOST_ECAM) {
                            current_is_pci_host = true;
                        } else if compatible.contains("operating-points-v2") {
                            // OPP table node: begin collecting its `opp`
                            // children's `opp-hz` properties.
                            opp_table_active = true;
                            opp_table_depth = current_depth;
                            current_table_phandle = node_phandle;
                            current_table_min = u64::MAX;
                            current_table_max = 0;
                            current_table_disabled = false;
                        }
                    }
                    Some("reg") => {
                        // Parse `reg` using the current node's address-cells and size-cells.
                        let ac = ctx.address_cells as usize;
                        let sc = ctx.size_cells as usize;
                        let cell_bytes = 4;
                        let entry_bytes = (ac + sc) * cell_bytes;

                        if entry_bytes == 0 || value_len < entry_bytes {
                            continue;
                        }

                        // Iterate over all (address, size) entries in the reg value.
                        let entry_count = value_len / entry_bytes;
                        for entry_idx in 0..entry_count {
                            let entry_ptr = unsafe { value_ptr.add(entry_idx * entry_bytes) };

                            let mut addr: u64 = 0;
                            for i in 0..ac {
                                let cell = unsafe { read_u32_be(entry_ptr, i * cell_bytes) } as u64;
                                addr = (addr << 32) | cell;
                            }
                            let entry_size: u64 = {
                                let mut s: u64 = 0;
                                for i in 0..sc {
                                    let cell =
                                        unsafe { read_u32_be(entry_ptr, (ac + i) * cell_bytes) }
                                            as u64;
                                    s = (s << 32) | cell;
                                }
                                s
                            };

                            // /memory node: capture base and size for physical RAM detection.
                            if current_is_memory_node {
                                info.memory_base = Some(addr as usize);
                                info.memory_size = Some(entry_size as usize);
                                node_pending_memory_base = addr;
                                node_pending_memory_size = entry_size;
                                node_has_memory_reg = true;
                                if let Some(nid) = pending_memory_node_id {
                                    fdt_numa.add_memory(nid, addr, addr + entry_size);
                                }
                            }

                            // GIC distributor: first reg entry in the GIC node.
                            if (0x0800_0000..0x0801_0000).contains(&addr)
                                && (info.gicd_base.is_none()
                                    || (info.gicd_base == Some(0x0800_0000) && addr != 0x0800_0000))
                            {
                                info.gicd_base = Some(addr as usize);
                            }
                            // GIC CPU interface: second reg entry (GICv2 only).
                            if (0x0801_0000..0x0802_0000).contains(&addr) {
                                info.gicc_base = Some(addr as usize);
                            }
                            // GICv3 redistributor base: second reg entry in GICv3 node.
                            if current_is_gicv3 && entry_idx == 1 {
                                info.gicr_base = Some(addr as usize);
                            }
                            // GICv3 ITS base: first reg entry in ITS node.
                            if current_is_its && entry_idx == 0 {
                                info.its_base = Some(addr as usize);
                            }
                            // UART (PL011): typically at 0x0900_0000.
                            // UART (NS16550A): RISC-V virt at 0x1000_0000.
                            if ((0x0900_0000..0x0910_0000).contains(&addr) && addr != 0x0901_0000)
                                || (0x1000_0000..0x1000_1000).contains(&addr)
                            {
                                info.uart_base = Some(addr as usize);
                            }
                            // RTC (PL031): QEMU virt places it at 0x0901_0000.
                            // RTC (Goldfish): RISC-V virt at 0x0010_1000.
                            if addr == 0x0901_0000 || addr == 0x0010_1000 {
                                info.rtc_base = Some(addr as usize);
                            }
                            // RISC-V PLIC: QEMU virt at 0x0C00_0000.
                            if (0x0C00_0000..0x0D00_0000).contains(&addr) {
                                info.plic_base = Some(addr as usize);
                            }
                            // PCIe ECAM: capture from pci-host-ecam-generic node.
                            if current_is_pci_host
                                && info.ecam_base.is_none()
                                && !(0x0A00_0000..0x0A20_0000).contains(&addr)
                                && !(0x1000_1000..0x1001_0000).contains(&addr)
                                && !(0x0C00_0000..0x0D00_0000).contains(&addr)
                            {
                                info.ecam_base = Some(addr as usize);
                            }
                            // VirtIO MMIO: aarch64 at 0x0A00_0000, riscv64 at 0x1000_1000.
                            if ((0x0A00_0000..0x0A20_0000).contains(&addr)
                                || (0x1000_1000..0x1001_0000).contains(&addr))
                                && virtio_mmio_idx < virtio_mmio_bases.len()
                            {
                                virtio_mmio_bases[virtio_mmio_idx] = Some(addr as usize);
                                virtio_mmio_idx += 1;
                            }
                        }
                    }
                    Some("bus-range") if value_len >= 8 && current_is_pci_host => {
                        // bus-range is two u32 cells: first bus, last bus.
                        let first_bus = unsafe { read_u32_be(value_ptr, 0) };
                        let last_bus = unsafe { read_u32_be(value_ptr, 4) };
                        if first_bus <= last_bus && last_bus <= 255 {
                            info.ecam_start_bus = Some(first_bus as u8);
                            info.ecam_end_bus = Some(last_bus as u8);
                        }
                    }
                    // RISC-V: the timer/counter rate is the CPU `timebase-frequency`
                    // property on the /cpus node (a single u32 cell).  Must take
                    // priority over any peripheral `clock-frequency` below, so it is
                    // ungated (only the is_none guard applies).
                    Some("timebase-frequency")
                        if value_len >= 4 && info.timer_frequency.is_none() =>
                    {
                        let freq = unsafe { read_u32_be(value_ptr, 0) } as u64;
                        info.timer_frequency = Some(freq);
                    }
                    // Generic clock-frequency is only the timer rate on timer/CPU
                    // nodes; a 16550 UART or APB clock-frequency (e.g. 3,686,400 on
                    // riscv64 virt, 24 MHz on aarch64 virt) must never win the timer.
                    Some("clock-frequency")
                        if value_len >= 4
                            && info.timer_frequency.is_none()
                            && in_timer_or_cpu_node =>
                    {
                        // Timer clock-frequency is a single u32 (or u64 on some platforms).
                        let freq_hi = unsafe { read_u32_be(value_ptr, 0) } as u64;
                        if value_len >= 8 {
                            let freq_lo = unsafe { read_u32_be(value_ptr, 4) } as u64;
                            info.timer_frequency = Some((freq_hi << 32) | freq_lo);
                        } else {
                            info.timer_frequency = Some(freq_hi);
                        }
                    }
                    Some("riscv,isa") if value_len > 0 && !info.has_sstc => {
                        // The RISC-V ISA string (e.g. "rv64imafdc_sstc_zicbom").
                        // Check for the "_sstc" or "sstc_" substring indicating the
                        // Sstc (Supervisor Timer Compare) extension is present.
                        let isa_bytes =
                            unsafe { core::slice::from_raw_parts(value_ptr, value_len.min(256)) };
                        if let Ok(isa_str) = core::str::from_utf8(isa_bytes) {
                            info.has_sstc = isa_str.contains("sstc");
                        }
                    }
                    Some("numa-node-id") if value_len >= 4 => {
                        let node_id = unsafe { read_u32_be(value_ptr, 0) } as u8;
                        // CPU node: associate the current CPU index with the node.
                        if cpu_node_idx >= 0 {
                            fdt_numa.add_cpu(cpu_node_idx as u32, node_id);
                        }
                        // Memory node: associate with the pending memory range.
                        if current_is_memory_node {
                            pending_memory_node_id = Some(node_id);
                            if node_has_memory_reg {
                                fdt_numa.add_memory(
                                    node_id,
                                    node_pending_memory_base,
                                    node_pending_memory_base + node_pending_memory_size,
                                );
                            }
                        }
                    }
                    Some("distance-matrix") if current_is_distance_map && value_len >= 12 => {
                        // distance-matrix is a sequence of triplets:
                        // (local_node, remote_node, distance) each as a u32 cell.
                        const CELL: usize = 4;
                        const TRIPLET: usize = CELL * 3;
                        let entry_count = value_len / TRIPLET;
                        for i in 0..entry_count {
                            let ep = unsafe { value_ptr.add(i * TRIPLET) };
                            let local = unsafe { read_u32_be(ep, 0) };
                            let remote = unsafe { read_u32_be(ep, CELL) };
                            let distance = unsafe { read_u32_be(ep, CELL * 2) } as u8;
                            fdt_numa.set_distance(local, remote, distance);
                        }
                    }
                    Some("phandle") if value_len >= 4 => {
                        node_phandle = Some(unsafe { read_u32_be(value_ptr, 0) });
                        // Some DTs place `compatible` before `phandle`; pick
                        // the table's phandle up even in that case.
                        if opp_table_active && current_depth == opp_table_depth {
                            current_table_phandle = node_phandle;
                        }
                    }
                    Some("status") if value_len >= 1 => {
                        let status = core::str::from_utf8(unsafe {
                            core::slice::from_raw_parts(value_ptr, value_len.min(16))
                        })
                        .unwrap_or("");
                        if status.contains("disabled") {
                            if opp_table_active && current_depth == opp_table_depth {
                                current_table_disabled = true;
                            } else if opp_table_active && current_depth > opp_table_depth {
                                opp_node_disabled = true;
                            }
                        }
                    }
                    Some("opp-hz") if opp_table_active && current_depth > opp_table_depth => {
                        // `opp-hz` is a frequency in Hz, encoded as one or two
                        // 32-bit big-endian cells (u32 or u64 value).
                        let hz = if value_len >= 8 {
                            let hi = unsafe { read_u32_be(value_ptr, 0) } as u64;
                            let lo = unsafe { read_u32_be(value_ptr, 4) } as u64;
                            (hi << 32) | lo
                        } else if value_len >= 4 {
                            (unsafe { read_u32_be(value_ptr, 0) }) as u64
                        } else {
                            0
                        };
                        if hz != 0 {
                            opp_node_hz = Some(hz);
                        }
                    }
                    Some("operating-points") if value_len >= 8 && cpu_node_idx >= 0 => {
                        // Legacy OPP tuples on a CPU node:
                        // (freq_hz, volt_uv) pairs, each a u32 cell.
                        let mut i = 0usize;
                        while i + 8 <= value_len {
                            let freq = unsafe { read_u32_be(value_ptr, i) } as u64;
                            if freq != 0 {
                                legacy_opp_min = legacy_opp_min.min(freq);
                                legacy_opp_max = legacy_opp_max.max(freq);
                                legacy_opp_found = true;
                            }
                            i += 8;
                        }
                    }
                    Some("operating-points-v2") if value_len >= 4 && cpu_node_idx >= 0 => {
                        // CPU node references an OPP table via phandle(s).
                        if cpu_opp_count < cpu_opp_phandles.len() {
                            cpu_opp_phandles[cpu_opp_count] = unsafe { read_u32_be(value_ptr, 0) };
                            cpu_opp_count += 1;
                        }
                    }
                    _ => { /* ignore unknown properties */ }
                }
            }

            FDT_END => {
                break;
            }

            _ => {
                // Unknown token — the FDT is malformed or we've lost sync.
                break;
            }
        }
    }

    // ── Resolve CPU-referenced OPP tables into a frequency range ───────
    // Union the ranges of every OPP table referenced by a CPU node, plus any
    // legacy `operating-points` tuples found directly on CPU nodes.
    let mut min_hz = u64::MAX;
    let mut max_hz = 0u64;
    let mut found = false;
    for &cpu_ph in &cpu_opp_phandles[..cpu_opp_count] {
        for &(ph, t_min, t_max) in &opp_tables[..opp_table_count] {
            if ph == cpu_ph {
                min_hz = min_hz.min(t_min);
                max_hz = max_hz.max(t_max);
                found = true;
                break;
            }
        }
    }
    if legacy_opp_found {
        min_hz = min_hz.min(legacy_opp_min);
        max_hz = max_hz.max(legacy_opp_max);
        found = true;
    }
    if found && min_hz <= max_hz {
        info.cpu_freq_min_hz = Some(min_hz);
        info.cpu_freq_max_hz = Some(max_hz);
    }

    // Post-process VirtIO MMIO: compute base, stride, and count.
    if virtio_mmio_idx > 0 {
        // Sort the bases (they should already be in order in QEMU's FDT).
        let mut sorted: [Option<usize>; 8] = [None; 8];
        let mut count = 0;
        for &base in &virtio_mmio_bases {
            if let Some(b) = base {
                // Insertion-sort into sorted.
                let mut pos = count;
                while pos > 0 {
                    if let Some(s) = sorted[pos - 1] {
                        if s > b {
                            sorted[pos] = sorted[pos - 1];
                            pos -= 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                sorted[pos] = Some(b);
                count += 1;
            }
        }

        if count > 0 {
            let base = sorted[0].unwrap();
            info.virtio_mmio_base = Some(base);
            info.virtio_mmio_count = Some(count);

            if count >= 2 {
                if let Some(next) = sorted[1] {
                    info.virtio_mmio_stride = Some(next - base);
                }
            }
            // Fallback stride: use QEMU's standard 0x200.
            if info.virtio_mmio_stride.is_none() {
                info.virtio_mmio_stride = Some(0x200);
            }
        }
    }

    // Store NUMA info discovered during the FDT walk.
    store_fdt_numa_info(fdt_numa);

    // Populate the device-tree node table (used for device-tree-driven
    // driver probing) with a second, self-contained walk of the same blob.
    store_dt_nodes(collect_dt_nodes(fdt_addr));

    info
}

// ---------------------------------------------------------------------------
// Device-tree node table (device-tree-driven driver probe)
// ---------------------------------------------------------------------------

/// Maximum number of DT nodes recorded in the node table.
pub const MAX_DT_NODES: usize = 32;

/// One (address, size) pair from a node's `reg` property.
#[derive(Debug, Clone, Copy, Default)]
pub struct DtRegEntry {
    pub base: u64,
    pub size: u64,
}

/// A device-tree node carrying the properties drivers need to probe a device:
/// compatible string, MMIO `reg` entries, interrupt specifier, phandle, status.
///
/// Fixed-size (no heap) so it can be built while the FDT is parsed during
/// early boot, mirroring [`PlatformInfo`].  The whole table is `Copy`, so
/// drivers snapshot it cheaply at probe time.
#[derive(Debug, Clone, Copy)]
pub struct DtNode {
    /// Unit name (`virtio_mmio` from `virtio@a000000`), NUL-terminated.
    pub name: [u8; 24],
    pub name_len: u8,
    /// First `compatible` string, NUL-terminated.
    pub compatible: [u8; 64],
    pub compatible_len: u8,
    /// `reg` entries parsed with the node's #address-cells / #size-cells.
    pub reg: [DtRegEntry; 2],
    pub reg_count: u8,
    /// First `interrupts` cell, if any.
    pub irq: Option<u32>,
    /// `phandle` property, if any.
    pub phandle: Option<u32>,
    /// True when `status` is "disabled".
    pub disabled: bool,
    /// Node depth (0 = root).
    pub depth: u8,
}

impl DtNode {
    const fn empty() -> Self {
        Self {
            name: [0; 24],
            name_len: 0,
            compatible: [0; 64],
            compatible_len: 0,
            reg: [DtRegEntry { base: 0, size: 0 }; 2],
            reg_count: 0,
            irq: None,
            phandle: None,
            disabled: false,
            depth: 0,
        }
    }

    /// The unit name as a `&str` (empty if unset).
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    /// The first compatible string as a `&str` (empty if unset).
    pub fn compatible_str(&self) -> &str {
        core::str::from_utf8(&self.compatible[..self.compatible_len as usize]).unwrap_or("")
    }

    /// Base address of the first `reg` entry (the device's MMIO window).
    pub fn mmio_base(&self) -> Option<usize> {
        if self.reg_count > 0 {
            Some(self.reg[0].base as usize)
        } else {
            None
        }
    }
}

/// Fixed-size table of discovered device-tree nodes.
#[derive(Debug, Clone, Copy)]
pub struct DtNodeTable {
    pub nodes: [DtNode; MAX_DT_NODES],
    pub count: usize,
}

impl DtNodeTable {
    pub const fn empty() -> Self {
        Self {
            nodes: [DtNode::empty(); MAX_DT_NODES],
            count: 0,
        }
    }

    /// Iterate the recorded nodes.
    pub fn iter(&self) -> impl Iterator<Item = &DtNode> {
        self.nodes[..self.count].iter()
    }
}

/// Node table discovered from the FDT, populated by [`parse_fdt`].
static DT_NODES: SpinLock<DtNodeTable> = SpinLock::new(DtNodeTable::empty());

/// Store a device-tree node table (called by [`parse_fdt`] during boot).
pub fn store_dt_nodes(table: DtNodeTable) {
    *DT_NODES.lock() = table;
}

/// Return a copy of the device-tree node table.
///
/// Empty until the FDT has been parsed (`parse_fdt` / `collect_dt_nodes`).
pub fn dt_node_table() -> DtNodeTable {
    *DT_NODES.lock()
}

/// Walk the flattened device tree at `fdt_addr` and build a table of device
/// nodes with the properties drivers use to probe devices (compatible string,
/// MMIO `reg` entries, interrupt specifier, phandle, status).
///
/// Returns an empty table on malformed input.  Called by [`parse_fdt`] during
/// early boot so the node table is ready before the driver manager probes
/// devices; also directly testable against a synthetic FDT.
pub fn collect_dt_nodes(fdt_addr: usize) -> DtNodeTable {
    let mut table = DtNodeTable::empty();
    if fdt_addr == 0 {
        return table;
    }

    let base = fdt_addr as *const u8;

    // Validate the header exactly like `parse_fdt`.
    let magic = unsafe { read_u32_be(base, OFF_MAGIC) };
    if magic != FDT_MAGIC {
        return table;
    }
    let version = unsafe { read_u32_be(base, OFF_VERSION) };
    let last_comp_version = unsafe { read_u32_be(base, OFF_LAST_COMP_VERSION) };
    if version < 17 || last_comp_version > 17 {
        return table;
    }

    let totalsize = unsafe { read_u32_be(base, OFF_TOTALSIZE) } as usize;
    let off_dt_struct = unsafe { read_u32_be(base, OFF_OFF_DT_STRUCT) } as usize;
    let off_dt_strings = unsafe { read_u32_be(base, OFF_OFF_DT_STRINGS) } as usize;

    if off_dt_struct >= totalsize || off_dt_strings >= totalsize || off_dt_struct >= off_dt_strings
    {
        return table;
    }

    let strings_base = unsafe { base.add(off_dt_strings) };
    let strings_size = totalsize - off_dt_strings;
    let struct_ptr = unsafe { base.add(off_dt_struct) };
    let struct_end = unsafe { base.add(off_dt_strings) };

    /// Track #address-cells / #size-cells per depth (inherited from parents).
    #[derive(Clone, Copy)]
    struct Cells {
        address: u32,
        size: u32,
    }
    let root_cells = Cells {
        address: 2,
        size: 2,
    };
    let mut cells: [Cells; 16] = [root_cells; 16];
    // Pending node being accumulated between BEGIN_NODE and END_NODE,
    // indexed by the node's own depth (1 = direct child of the root).
    let mut pending: [Option<DtNode>; 16] = [None; 16];
    let mut depth: usize = 0;

    fn align4(ptr: *const u8, base_ptr: *const u8) -> *const u8 {
        let offset = (ptr as usize).wrapping_sub(base_ptr as usize);
        let aligned = (offset + 3) & !3;
        unsafe { base_ptr.add(aligned) }
    }

    let mut ptr = struct_ptr;

    while ptr < struct_end {
        if ptr.wrapping_offset(4) > struct_end {
            break;
        }

        let token = unsafe { read_u32_be(ptr, 0) };
        ptr = unsafe { ptr.add(4) };

        match token {
            FDT_BEGIN_NODE => {
                // Node name: NUL-terminated string.
                let name_start = ptr;
                let mut name_len = 0usize;
                while ptr < struct_end && unsafe { *ptr } != 0 {
                    ptr = unsafe { ptr.add(1) };
                    name_len += 1;
                }
                if ptr < struct_end {
                    ptr = unsafe { ptr.add(1) };
                }
                ptr = align4(ptr, base);

                let raw_name = core::str::from_utf8(unsafe {
                    core::slice::from_raw_parts(name_start, name_len)
                })
                .unwrap_or("");

                // Enter the node: its own depth is the parent depth + 1.
                let node_depth = depth + 1;
                depth = node_depth;
                if depth < cells.len() {
                    cells[depth] = cells[depth - 1];
                }
                if node_depth >= pending.len() {
                    continue;
                }

                let unit = raw_name.split('@').next().unwrap_or(raw_name);
                if unit.is_empty() {
                    // Root node — not a probable device.
                    pending[node_depth] = None;
                    continue;
                }

                let mut node = DtNode::empty();
                node.depth = (node_depth - 1).min(255) as u8;
                let nlen = core::cmp::min(unit.len(), node.name.len() - 1);
                node.name[..nlen].copy_from_slice(&unit.as_bytes()[..nlen]);
                node.name_len = nlen as u8;
                pending[node_depth] = Some(node);
            }

            FDT_END_NODE => {
                if depth < pending.len() {
                    if let Some(node) = pending[depth].take() {
                        if table.count < MAX_DT_NODES {
                            table.nodes[table.count] = node;
                            table.count += 1;
                        }
                    }
                }
                depth = depth.saturating_sub(1);
            }

            FDT_PROP => {
                if ptr.wrapping_offset(8) > struct_end {
                    break;
                }
                let len = unsafe { read_u32_be(ptr, 0) } as usize;
                let nameoff = unsafe { read_u32_be(ptr, 4) } as usize;
                ptr = unsafe { ptr.add(8) };

                let prop_name = unsafe { read_str(strings_base, strings_size, nameoff) };

                let value_ptr = ptr;
                let value_len = len;
                ptr = unsafe { ptr.add(len) };
                ptr = align4(ptr, base);

                if value_len == 0 || value_ptr.wrapping_add(value_len) > struct_end {
                    continue;
                }

                let Some(prop) = prop_name else { continue };
                let Some(node) = pending.get_mut(depth).and_then(|slot| slot.as_mut()) else {
                    continue;
                };

                match prop {
                    "#address-cells" if value_len >= 4 => {
                        let ac = unsafe { read_u32_be(value_ptr, 0) };
                        if depth < cells.len() {
                            cells[depth].address = ac;
                        }
                    }
                    "#size-cells" if value_len >= 4 => {
                        let sc = unsafe { read_u32_be(value_ptr, 0) };
                        if depth < cells.len() {
                            cells[depth].size = sc;
                        }
                    }
                    "compatible" => {
                        // Copy the first NUL-terminated compatible string.
                        let bytes = unsafe { core::slice::from_raw_parts(value_ptr, value_len) };
                        let first = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
                        let clen = core::cmp::min(first.len(), node.compatible.len() - 1);
                        node.compatible[..clen].copy_from_slice(&first[..clen]);
                        node.compatible_len = clen as u8;
                    }
                    "reg" => {
                        let c = cells[depth.min(cells.len() - 1)];
                        let ac = c.address as usize;
                        let sc = c.size as usize;
                        let entry_bytes = (ac + sc) * 4;
                        if entry_bytes == 0 || value_len < entry_bytes {
                            continue;
                        }
                        let entries = core::cmp::min(value_len / entry_bytes, node.reg.len());
                        for i in 0..entries {
                            let ep = unsafe { value_ptr.add(i * entry_bytes) };
                            let mut addr: u64 = 0;
                            for cell in 0..ac {
                                let v = unsafe { read_u32_be(ep, cell * 4) } as u64;
                                addr = (addr << 32) | v;
                            }
                            let mut size: u64 = 0;
                            for cell in 0..sc {
                                let v = unsafe { read_u32_be(ep, (ac + cell) * 4) } as u64;
                                size = (size << 32) | v;
                            }
                            node.reg[i] = DtRegEntry { base: addr, size };
                            node.reg_count = (i + 1) as u8;
                        }
                    }
                    "interrupts" if value_len >= 4 => {
                        node.irq = Some(unsafe { read_u32_be(value_ptr, 0) });
                    }
                    "phandle" if value_len >= 4 => {
                        node.phandle = Some(unsafe { read_u32_be(value_ptr, 0) });
                    }
                    "status" => {
                        let status = core::str::from_utf8(unsafe {
                            core::slice::from_raw_parts(value_ptr, value_len.min(16))
                        })
                        .unwrap_or("");
                        if status.contains("disabled") {
                            node.disabled = true;
                        }
                    }
                    _ => {}
                }
            }

            FDT_END => break,
            _ => break,
        }
    }

    table
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Build a minimal synthetic FDT for a QEMU virt-like platform in a
    /// `Vec<u8>` and verify that `parse_fdt` extracts the right addresses.
    ///
    /// The test blob contains:
    /// - root node with #address-cells=2, #size-cells=2
    /// - /intc (GIC-400) with reg = <0x0 0x0800_0000 0x0 0x10000>,
    ///   <0x0 0x0801_0000 0x0 0x10000>
    /// - /pl011@9000000 with reg = <0x0 0x0900_0000 0x0 0x1000>
    /// - /virtio_mmio@a000000 with reg = <0x0 0x0A00_0000 0x0 0x200>
    /// - /virtio_mmio@a000200 with reg = <0x0 0x0A00_0200 0x0 0x200>
    fn build_qemu_virt_fdt() -> Vec<u8> {
        // We construct a minimal but valid FDT v17 for testing.
        // Structure: header + mem_rsvmap (empty) + struct block + strings block.

        let mut strings = Vec::<u8>::new();
        let mut str_off = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };

        // Pre-register all string offsets.
        let off_model = str_off("model"); // 0
        let off_compatible = str_off("compatible"); // 6+1=7
        let off_addr_cells = str_off("#address-cells"); // 17+1=18
        let off_size_cells = str_off("#size-cells"); // 33+1=34
        let off_reg = str_off("reg"); // 46+1=47
        let off_clock_freq = str_off("clock-frequency"); // 50+1=51
        let _off_phandle = str_off("phandle"); // 67+1=68
        let _off_int_controller = str_off("interrupt-controller"); // 75+1=76
        let _off_virtio_mmio_compat = str_off("virtio,mmio"); // 97+1=98
        let _off_arm_pl011 = str_off("arm,pl011"); // 110+1=111
        let _off_arm_gic400 = str_off("arm,gic-400"); // 120+1=121

        // Use u32::from_be_bytes for embedded big-endian values.
        fn be32(v: u32) -> [u8; 4] {
            v.to_be_bytes()
        }

        let mut sblock = Vec::<u8>::new();

        // FDT_BEGIN_NODE: root "" (empty name = root)
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.push(0); // empty name + NUL
        sblock.extend_from_slice(&[0, 0, 0]); // align to 4 bytes

        // prop: #address-cells = 2
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(4)); // len
        sblock.extend_from_slice(&off_addr_cells.to_be_bytes());
        sblock.extend_from_slice(&be32(2));

        // prop: #size-cells = 2
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(4));
        sblock.extend_from_slice(&off_size_cells.to_be_bytes());
        sblock.extend_from_slice(&be32(2));

        // prop: model = "linux,dummy-virt"
        let model_str = "linux,dummy-virt";
        let off_model2 = str_off(model_str);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(model_str.len() as u32));
        sblock.extend_from_slice(&off_model.to_be_bytes());
        sblock.extend_from_slice(model_str.as_bytes());
        // pad to 4
        if !model_str.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - model_str.len() % 4)]);
        }

        // prop: compatible for root = "linux,dummy-virt"
        // (reuse model string "linux,dummy-virt" — in practice these differ)
        let off_model_str = off_model2;
        let _ = off_model_str;

        // -- intc node --
        let name_intc = b"intc\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_intc);
        // pad to 4: name_intc is 5 bytes (i,n,t,c,\0), needs 3 bytes padding
        let pad_intc = (4 - (name_intc.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_intc]);

        // compatible = "arm,gic-400"
        let compat_gic = "arm,gic-400";
        let _off_compat_gic = str_off(compat_gic);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_gic.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_gic.as_bytes());
        if !compat_gic.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_gic.len() % 4)]);
        }

        // reg = <0x0 0x0800_0000 0x0 0x10000>, <0x0 0x0801_0000 0x0 0x10000>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(32)); // 2 entries * (2 addr + 2 size) * 4 bytes
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        // Entry 1: GICD
        sblock.extend_from_slice(&be32(0x0000_0000)); // addr hi
        sblock.extend_from_slice(&be32(0x0800_0000)); // addr lo
        sblock.extend_from_slice(&be32(0x0000_0000)); // size hi
        sblock.extend_from_slice(&be32(0x0001_0000)); // size lo
                                                      // Entry 2: GICC
        sblock.extend_from_slice(&be32(0x0000_0000)); // addr hi
        sblock.extend_from_slice(&be32(0x0801_0000)); // addr lo
        sblock.extend_from_slice(&be32(0x0000_0000)); // size hi
        sblock.extend_from_slice(&be32(0x0001_0000)); // size lo

        // END_NODE intc
        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- pl011@9000000 node --
        let name_uart = b"pl011@9000000\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_uart);
        let pad_uart = (4 - (name_uart.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_uart]);

        // compatible = "arm,pl011"
        let compat_uart = "arm,pl011";
        let _off_compat_uart = str_off(compat_uart);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_uart.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_uart.as_bytes());
        // pad
        if !compat_uart.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_uart.len() % 4)]);
        }

        // reg = <0x0 0x0900_0000 0x0 0x1000>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0900_0000));
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0000_1000));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- pl031@9010000 node --
        let name_rtc = b"pl031@9010000\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_rtc);
        let pad_rtc = (4 - (name_rtc.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_rtc]);

        // compatible = "arm,pl031"
        let compat_rtc = "arm,pl031";
        let _off_compat_rtc = str_off(compat_rtc);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_rtc.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_rtc.as_bytes());
        if !compat_rtc.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_rtc.len() % 4)]);
        }

        // reg = <0x0 0x0901_0000 0x0 0x1000>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0901_0000));
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0000_1000));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- plic@c000000 node (RISC-V PLIC) --
        let name_plic = b"plic@c000000\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_plic);
        let pad_plic = (4 - (name_plic.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_plic]);

        // compatible = "riscv,plic0"
        let compat_plic = "riscv,plic0";
        let _off_compat_plic = str_off(compat_plic);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_plic.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_plic.as_bytes());
        if !compat_plic.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_plic.len() % 4)]);
        }

        // reg = <0x0 0x0C00_0000 0x0 0x40_0000>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0C00_0000));
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0040_0000));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- virtio_mmio@a000000 node --
        let name_virtio0 = b"virtio@a000000\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_virtio0);
        let pad_v0 = (4 - (name_virtio0.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_v0]);

        // compatible = "virtio,mmio"
        let compat_virtio = "virtio,mmio";
        let _off_compat_virtio = str_off(compat_virtio);
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_virtio.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_virtio.as_bytes());
        if !compat_virtio.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_virtio.len() % 4)]);
        }

        // reg = <0x0 0x0A00_0000 0x0 0x200>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0A00_0000));
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0000_0200));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- virtio_mmio@a000200 node --
        let name_virtio1 = b"virtio@a000200\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_virtio1);
        let pad_v1 = (4 - (name_virtio1.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_v1]);

        // compatible = "virtio,mmio"
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(compat_virtio.len() as u32));
        sblock.extend_from_slice(&off_compatible.to_be_bytes());
        sblock.extend_from_slice(compat_virtio.as_bytes());
        if !compat_virtio.len().is_multiple_of(4) {
            sblock.extend_from_slice(&[0u8; 4][..(4 - compat_virtio.len() % 4)]);
        }

        // reg = <0x0 0x0A00_0200 0x0 0x200>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0A00_0200));
        sblock.extend_from_slice(&be32(0x0000_0000));
        sblock.extend_from_slice(&be32(0x0000_0200));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- timer node with clock-frequency --
        let name_timer = b"timer\0";
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name_timer);
        let pad_timer = (4 - (name_timer.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad_timer]);

        // clock-frequency = 62500000 (QEMU virt default, as a single u32 cell)
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(4));
        sblock.extend_from_slice(&off_clock_freq.to_be_bytes());
        sblock.extend_from_slice(&be32(62_500_000));

        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- END root --
        sblock.extend_from_slice(&be32(FDT_END_NODE));

        // -- END of structure block --
        sblock.extend_from_slice(&be32(FDT_END));

        // Pad strings block to align to 4 bytes for clean totalsize.
        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }

        let off_mem_rsvmap = 40; // right after header
        let off_dt_struct = off_mem_rsvmap + 16; // 16 bytes for empty mem_rsvmap terminator
        let off_dt_strings = off_dt_struct + sblock.len();

        let totalsize = off_dt_strings + strings.len();

        // Compute size_dt_struct (needed for header).
        let size_dt_struct = sblock.len() as u32;
        let size_dt_strings = strings.len() as u32;

        // Build the header.
        let mut header = Vec::<u8>::with_capacity(40);
        header.extend_from_slice(&be32(FDT_MAGIC)); // 0
        header.extend_from_slice(&be32(totalsize as u32)); // 4
        header.extend_from_slice(&be32(off_dt_struct as u32)); // 8
        header.extend_from_slice(&be32(off_dt_strings as u32)); // 12
        header.extend_from_slice(&be32(off_mem_rsvmap as u32)); // 16
        header.extend_from_slice(&be32(17)); // version = 17
        header.extend_from_slice(&be32(16)); // last_comp_version = 16
        header.extend_from_slice(&be32(0)); // boot_cpuid_phys
        header.extend_from_slice(&be32(size_dt_strings)); // size_dt_strings
        header.extend_from_slice(&be32(size_dt_struct)); // size_dt_struct

        assert_eq!(header.len(), 40);

        // Assemble the full FDT.
        let mut blob = Vec::<u8>::with_capacity(totalsize);
        blob.extend_from_slice(&header);
        // Empty memory reservation map (16 zero bytes).
        blob.extend_from_slice(&[0u8; 16]);
        blob.extend_from_slice(&sblock);
        blob.extend_from_slice(&strings);

        // Verify total size matches.
        assert_eq!(blob.len(), totalsize);

        blob
    }

    #[test]
    fn parse_fdt_rejects_null_pointer() {
        let info = parse_fdt(0);
        assert!(info.gicd_base.is_none());
        assert!(info.gicc_base.is_none());
        assert!(info.uart_base.is_none());
        assert!(info.virtio_mmio_base.is_none());
    }

    #[test]
    fn parse_fdt_rejects_bad_magic() {
        let mut blob = [0u8; 40];
        blob[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
        let info = parse_fdt(blob.as_ptr() as usize);
        assert!(info.gicd_base.is_none());
    }

    #[test]
    fn parse_fdt_extracts_qemu_virt_platform_info() {
        let blob = build_qemu_virt_fdt();
        let info = parse_fdt(blob.as_ptr() as usize);

        assert_eq!(info.gicd_base, Some(0x0800_0000));
        assert_eq!(info.gicc_base, Some(0x0801_0000));
        assert_eq!(info.uart_base, Some(0x0900_0000));
        assert_eq!(info.rtc_base, Some(0x0901_0000));
        assert_eq!(info.plic_base, Some(0x0C00_0000));
        assert_eq!(info.virtio_mmio_base, Some(0x0A00_0000));
        assert_eq!(info.virtio_mmio_stride, Some(0x200));
        assert_eq!(info.virtio_mmio_count, Some(2));
    }

    #[test]
    fn parse_fdt_extracts_timer_frequency() {
        let blob = build_qemu_virt_fdt();
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.timer_frequency, Some(62_500_000));
    }

    // ── Small generic FDT builder for timer-frequency tests ──────────────

    /// Emit a single node with the given properties (all 4-byte values here)
    /// followed by FDT_END_NODE.
    fn emit_node(
        sblock: &mut Vec<u8>,
        name: &str,
        str_off: &mut dyn FnMut(&str) -> u32,
        props: &[(&str, &[u8])],
    ) {
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name.as_bytes());
        sblock.push(0);
        let pad = (4 - ((name.len() + 1) % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad]);
        for (pname, val) in props {
            let off = str_off(pname);
            sblock.extend_from_slice(&be32(FDT_PROP));
            sblock.extend_from_slice(&be32(val.len() as u32));
            sblock.extend_from_slice(&off.to_be_bytes());
            sblock.extend_from_slice(val);
            let padv = (4 - (val.len() % 4)) % 4;
            if padv > 0 {
                sblock.extend_from_slice(&[0u8; 4][..padv]);
            }
        }
        sblock.extend_from_slice(&be32(FDT_END_NODE));
    }

    /// Build a minimal valid FDT v17 whose struct block is emitted by `emit`
    /// (root node open/close are added automatically).
    fn build_small_fdt(emit: impl FnOnce(&mut Vec<u8>, &mut dyn FnMut(&str) -> u32)) -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut str_off = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };

        let mut sblock = Vec::<u8>::new();
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE)); // root ""
        sblock.push(0);
        sblock.extend_from_slice(&[0, 0, 0]);

        emit(&mut sblock, &mut str_off);

        sblock.extend_from_slice(&be32(FDT_END_NODE)); // end root
        sblock.extend_from_slice(&be32(FDT_END));

        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }

        let off_dt_struct = 40 + 16; // header + empty mem_rsvmap
        let off_dt_strings = off_dt_struct + sblock.len();
        let totalsize = off_dt_strings + strings.len();

        let mut header = Vec::<u8>::with_capacity(40);
        header.extend_from_slice(&be32(FDT_MAGIC));
        header.extend_from_slice(&be32(totalsize as u32));
        header.extend_from_slice(&be32(off_dt_struct as u32));
        header.extend_from_slice(&be32(off_dt_strings as u32));
        header.extend_from_slice(&be32(40)); // off_mem_rsvmap
        header.extend_from_slice(&be32(17)); // version
        header.extend_from_slice(&be32(16)); // last_comp_version
        header.extend_from_slice(&be32(0)); // boot_cpuid_phys
        header.extend_from_slice(&be32(strings.len() as u32));
        header.extend_from_slice(&be32(sblock.len() as u32));

        let mut blob = header;
        blob.extend_from_slice(&[0u8; 16]); // empty memory reservation map
        blob.extend_from_slice(&sblock);
        blob.extend_from_slice(&strings);
        blob
    }

    #[test]
    fn parse_fdt_riscv_timebase_frequency_wins_over_uart_clock() {
        // Mirrors riscv64 virt: /cpus has timebase-frequency = 10 MHz and the
        // 16550 UART carries clock-frequency = 3,686,400.  The timebase must win.
        let blob = build_small_fdt(|sblock, str_off| {
            emit_node(
                sblock,
                "cpus",
                str_off,
                &[("timebase-frequency", &be32(10_000_000))],
            );
            emit_node(
                sblock,
                "serial@10000000",
                str_off,
                &[("clock-frequency", &be32(3_686_400))],
            );
        });
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.timer_frequency, Some(10_000_000));
    }

    #[test]
    fn parse_fdt_uart_clock_frequency_does_not_set_timer() {
        // A peripheral (UART) clock-frequency alone must not become the timer
        // rate; aarch64 falls back to CNTFRQ when the timer node has none.
        let blob = build_small_fdt(|sblock, str_off| {
            emit_node(
                sblock,
                "serial@10000000",
                str_off,
                &[("clock-frequency", &be32(3_686_400))],
            );
        });
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.timer_frequency, None);
    }

    #[test]
    fn platform_info_empty_is_all_none() {
        let info = PlatformInfo::empty();
        assert!(info.gicd_base.is_none());
        assert!(info.gicc_base.is_none());
        assert!(info.uart_base.is_none());
        assert!(info.virtio_mmio_base.is_none());
        assert!(info.virtio_mmio_stride.is_none());
        assert!(info.virtio_mmio_count.is_none());
        assert!(info.timer_frequency.is_none());
        assert!(info.rtc_base.is_none());
        assert!(info.plic_base.is_none());
    }

    #[test]
    fn platform_info_store_and_retrieve_round_trip() {
        let mut info = PlatformInfo::empty();
        info.gicd_base = Some(0x0800_0000);
        info.gicc_base = Some(0x0801_0000);
        info.uart_base = Some(0x0900_0000);
        info.timer_frequency = Some(62_500_000);
        info.rtc_base = Some(0x0901_0000);

        store_platform_info(info);
        let retrieved = platform_info();

        assert_eq!(retrieved.gicd_base, Some(0x0800_0000));
        assert_eq!(retrieved.gicc_base, Some(0x0801_0000));
        assert_eq!(retrieved.uart_base, Some(0x0900_0000));
        assert_eq!(retrieved.timer_frequency, Some(62_500_000));
        assert_eq!(retrieved.rtc_base, Some(0x0901_0000));
    }

    #[test]
    fn platform_info_default_is_all_none() {
        // Re-store an empty info to reset after other tests.
        store_platform_info(PlatformInfo::empty());
        let info = platform_info();
        assert!(info.gicd_base.is_none());
        assert!(info.gicc_base.is_none());
        assert!(info.uart_base.is_none());
        assert!(info.virtio_mmio_base.is_none());
    }

    #[test]
    fn parse_fdt_survives_truncated_structure_block() {
        // A blob that is almost valid but the structure block ends mid-token.
        let mut blob = build_qemu_virt_fdt();
        // Truncate to remove the last few bytes of the structure block.
        let truncate_to = blob.len() - 50;
        blob.truncate(truncate_to);
        // Should not panic.
        let info = parse_fdt(blob.as_ptr() as usize);
        // May or may not have partial results; the important thing is no panic.
        let _ = info;
    }

    // ── DT node table (device-tree-driven driver probe) ─────────────────

    #[test]
    fn collect_dt_nodes_extracts_virtio_mmio_nodes() {
        let blob = build_qemu_virt_fdt();
        let table = collect_dt_nodes(blob.as_ptr() as usize);

        let virtio: Vec<&DtNode> = table
            .iter()
            .filter(|n| n.compatible_str() == "virtio,mmio")
            .collect();
        assert_eq!(virtio.len(), 2, "expected two virtio,mmio nodes");
        assert_eq!(virtio[0].name_str(), "virtio");
        assert_eq!(virtio[0].mmio_base(), Some(0x0A00_0000));
        assert_eq!(virtio[0].reg[0].size, 0x200);
        assert_eq!(virtio[1].mmio_base(), Some(0x0A00_0200));
    }

    #[test]
    fn collect_dt_nodes_records_all_device_nodes() {
        let blob = build_qemu_virt_fdt();
        let table = collect_dt_nodes(blob.as_ptr() as usize);

        let gic = table
            .iter()
            .find(|n| n.compatible_str() == "arm,gic-400")
            .expect("GIC node recorded");
        assert_eq!(gic.reg[0].base, 0x0800_0000);
        assert_eq!(gic.reg_count, 2);

        let uart = table
            .iter()
            .find(|n| n.compatible_str() == "arm,pl011")
            .expect("UART node");
        assert_eq!(uart.mmio_base(), Some(0x0900_0000));

        let rtc = table
            .iter()
            .find(|n| n.compatible_str() == "arm,pl031")
            .expect("RTC node");
        assert_eq!(rtc.mmio_base(), Some(0x0901_0000));

        let plic = table
            .iter()
            .find(|n| n.compatible_str() == "riscv,plic0")
            .expect("PLIC node");
        assert_eq!(plic.mmio_base(), Some(0x0C00_0000));

        // Nodes without a compatible string (timer) are still recorded.
        assert!(table.iter().any(|n| n.name_str() == "timer"));
    }

    #[test]
    fn collect_dt_nodes_rejects_bad_input() {
        assert_eq!(collect_dt_nodes(0).count, 0);
        let mut blob = [0u8; 40];
        blob[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
        assert_eq!(collect_dt_nodes(blob.as_ptr() as usize).count, 0);
    }

    /// Build a synthetic FDT exercising the node-table fields: an enabled
    /// virtio device with `reg` + `interrupts` + `phandle`, and a disabled one.
    fn build_dt_node_table_fdt() -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut str_off = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };
        let off_addr_cells = str_off("#address-cells");
        let off_size_cells = str_off("#size-cells");
        let off_compatible = str_off("compatible");
        let off_reg = str_off("reg");
        let off_interrupts = str_off("interrupts");
        let off_phandle = str_off("phandle");
        let off_status = str_off("status");

        let mut sblock = Vec::<u8>::new();
        // Root node.
        push_begin_node(&mut sblock, b"\0");
        push_prop_u32(&mut sblock, off_addr_cells, 2);
        push_prop_u32(&mut sblock, off_size_cells, 2);
        // Enabled virtio device.
        push_begin_node(&mut sblock, b"virtio@a000000\0");
        push_prop_string(&mut sblock, off_compatible, "virtio,mmio");
        // reg = <0x0 0x0A00_0000 0x0 0x200>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0));
        sblock.extend_from_slice(&be32(0x0A00_0000));
        sblock.extend_from_slice(&be32(0));
        sblock.extend_from_slice(&be32(0x200));
        push_prop_u32(&mut sblock, off_interrupts, 0x20);
        push_prop_u32(&mut sblock, off_phandle, 0x1234);
        push_end_node(&mut sblock);
        // Disabled virtio device (still carries reg, matching a real DT).
        push_begin_node(&mut sblock, b"virtio@a000200\0");
        push_prop_string(&mut sblock, off_compatible, "virtio,mmio");
        // reg = <0x0 0x0A00_0200 0x0 0x200>
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(16));
        sblock.extend_from_slice(&off_reg.to_be_bytes());
        sblock.extend_from_slice(&be32(0));
        sblock.extend_from_slice(&be32(0x0A00_0200));
        sblock.extend_from_slice(&be32(0));
        sblock.extend_from_slice(&be32(0x200));
        push_prop_string(&mut sblock, off_status, "disabled");
        push_end_node(&mut sblock);
        push_end_node(&mut sblock); // root

        assemble_fdt(&sblock, &strings)
    }

    #[test]
    fn collect_dt_nodes_captures_irq_phandle_and_disabled() {
        let blob = build_dt_node_table_fdt();
        let table = collect_dt_nodes(blob.as_ptr() as usize);

        let enabled = table
            .iter()
            .find(|n| n.mmio_base() == Some(0x0A00_0000))
            .expect("enabled virtio node");
        assert_eq!(enabled.irq, Some(0x20));
        assert_eq!(enabled.phandle, Some(0x1234));
        assert!(!enabled.disabled);

        let disabled = table
            .iter()
            .find(|n| n.mmio_base() == Some(0x0A00_0200))
            .expect("disabled virtio node");
        assert!(disabled.disabled);
    }

    // ── OPP table discovery tests ───────────────────────────────────────

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    fn push_begin_node(sblock: &mut Vec<u8>, name: &[u8]) {
        sblock.extend_from_slice(&be32(FDT_BEGIN_NODE));
        sblock.extend_from_slice(name);
        let pad = (4 - (name.len() % 4)) % 4;
        sblock.extend_from_slice(&[0u8; 4][..pad]);
    }

    fn push_end_node(sblock: &mut Vec<u8>) {
        sblock.extend_from_slice(&be32(FDT_END_NODE));
    }

    fn push_prop_u32(sblock: &mut Vec<u8>, name_off: u32, value: u32) {
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(4));
        sblock.extend_from_slice(&name_off.to_be_bytes());
        sblock.extend_from_slice(&be32(value));
    }

    fn push_prop_u64(sblock: &mut Vec<u8>, name_off: u32, value: u64) {
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(8));
        sblock.extend_from_slice(&name_off.to_be_bytes());
        sblock.extend_from_slice(&be32((value >> 32) as u32));
        sblock.extend_from_slice(&be32(value as u32));
    }

    fn push_prop_string(sblock: &mut Vec<u8>, name_off: u32, value: &str) {
        sblock.extend_from_slice(&be32(FDT_PROP));
        sblock.extend_from_slice(&be32(value.len() as u32 + 1));
        sblock.extend_from_slice(&name_off.to_be_bytes());
        sblock.extend_from_slice(value.as_bytes());
        sblock.push(0);
        while !sblock.len().is_multiple_of(4) {
            sblock.push(0);
        }
    }

    /// Assemble an FDT from a pre-built structure block and strings block.
    fn assemble_fdt(sblock: &[u8], strings: &[u8]) -> Vec<u8> {
        let off_mem_rsvmap = 40;
        let off_dt_struct = off_mem_rsvmap + 16;
        let off_dt_strings = off_dt_struct + sblock.len();
        let totalsize = off_dt_strings + strings.len();

        let mut header = Vec::<u8>::with_capacity(40);
        header.extend_from_slice(&be32(FDT_MAGIC));
        header.extend_from_slice(&be32(totalsize as u32));
        header.extend_from_slice(&be32(off_dt_struct as u32));
        header.extend_from_slice(&be32(off_dt_strings as u32));
        header.extend_from_slice(&be32(off_mem_rsvmap as u32));
        header.extend_from_slice(&be32(17)); // version
        header.extend_from_slice(&be32(16)); // last_comp_version
        header.extend_from_slice(&be32(0)); // boot_cpuid_phys
        header.extend_from_slice(&be32(strings.len() as u32));
        header.extend_from_slice(&be32(sblock.len() as u32));
        assert_eq!(header.len(), 40);

        let mut blob = Vec::<u8>::with_capacity(totalsize);
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&[0u8; 16]); // empty memory reservation map
        blob.extend_from_slice(sblock);
        blob.extend_from_slice(strings);
        assert_eq!(blob.len(), totalsize);
        blob
    }

    /// Build a synthetic FDT with an `operating-points-v2` OPP table.
    ///
    /// The table carries two enabled points (1.28 GHz and 1.6 GHz) plus, when
    /// `disabled_hz` is `Some`, a third point at that frequency whose `opp`
    /// node has `status = "disabled"`.
    fn build_opp_fdt(disabled_hz: Option<u64>) -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut str_off = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };
        let off_addr_cells = str_off("#address-cells");
        let off_size_cells = str_off("#size-cells");
        let off_compatible = str_off("compatible");
        let off_operating_points_v2 = str_off("operating-points-v2");
        let off_phandle = str_off("phandle");
        let off_opp_hz = str_off("opp-hz");
        let off_status = str_off("status");

        let mut s = Vec::<u8>::new();
        push_begin_node(&mut s, b"\0"); // root
        push_prop_u32(&mut s, off_addr_cells, 2);
        push_prop_u32(&mut s, off_size_cells, 2);

        push_begin_node(&mut s, b"cpus\0");
        push_prop_u32(&mut s, off_addr_cells, 1);
        push_prop_u32(&mut s, off_size_cells, 0);
        push_begin_node(&mut s, b"cpu@0\0");
        push_prop_u32(&mut s, off_operating_points_v2, 0x1);
        push_end_node(&mut s); // cpu@0
        push_end_node(&mut s); // cpus

        push_begin_node(&mut s, b"opp-table-cpu\0");
        push_prop_u32(&mut s, off_phandle, 0x1);
        push_prop_string(&mut s, off_compatible, "operating-points-v2");
        push_begin_node(&mut s, b"opp-1280000000\0");
        push_prop_u64(&mut s, off_opp_hz, 1_280_000_000);
        push_end_node(&mut s);
        push_begin_node(&mut s, b"opp-1600000000\0");
        push_prop_u64(&mut s, off_opp_hz, 1_600_000_000);
        push_end_node(&mut s);
        if let Some(hz) = disabled_hz {
            push_begin_node(&mut s, b"opp-disabled\0");
            push_prop_string(&mut s, off_status, "disabled");
            push_prop_u64(&mut s, off_opp_hz, hz);
            push_end_node(&mut s);
        }
        push_end_node(&mut s); // opp-table-cpu

        s.extend_from_slice(&be32(FDT_END));

        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }
        assemble_fdt(&s, &strings)
    }

    /// Build a synthetic FDT with a legacy `operating-points` tuple on the
    /// CPU node.
    fn build_legacy_opp_fdt() -> Vec<u8> {
        let mut strings = Vec::<u8>::new();
        let mut str_off = |s: &str| -> u32 {
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };
        let off_addr_cells = str_off("#address-cells");
        let off_size_cells = str_off("#size-cells");
        let off_operating_points = str_off("operating-points");

        let mut s = Vec::<u8>::new();
        push_begin_node(&mut s, b"\0"); // root
        push_prop_u32(&mut s, off_addr_cells, 2);
        push_prop_u32(&mut s, off_size_cells, 2);
        push_begin_node(&mut s, b"cpus\0");
        push_prop_u32(&mut s, off_addr_cells, 1);
        push_prop_u32(&mut s, off_size_cells, 0);
        push_begin_node(&mut s, b"cpu@0\0");
        // operating-points = <1280000000 1000000 1600000000 1100000>
        s.extend_from_slice(&be32(FDT_PROP));
        s.extend_from_slice(&be32(16));
        s.extend_from_slice(&off_operating_points.to_be_bytes());
        s.extend_from_slice(&be32(1_280_000_000));
        s.extend_from_slice(&be32(1_000_000));
        s.extend_from_slice(&be32(1_600_000_000));
        s.extend_from_slice(&be32(1_100_000));
        push_end_node(&mut s); // cpu@0
        push_end_node(&mut s); // cpus
        s.extend_from_slice(&be32(FDT_END));

        while !strings.len().is_multiple_of(4) {
            strings.push(0);
        }
        assemble_fdt(&s, &strings)
    }

    #[test]
    fn parse_fdt_extracts_opp_frequency_range() {
        let blob = build_opp_fdt(None);
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.cpu_freq_min_hz, Some(1_280_000_000));
        assert_eq!(info.cpu_freq_max_hz, Some(1_600_000_000));
    }

    #[test]
    fn parse_fdt_skips_disabled_opp_points() {
        let blob = build_opp_fdt(Some(3_000_000_000));
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.cpu_freq_min_hz, Some(1_280_000_000));
        assert_eq!(info.cpu_freq_max_hz, Some(1_600_000_000));
    }

    #[test]
    fn parse_fdt_extracts_legacy_operating_points() {
        let blob = build_legacy_opp_fdt();
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.cpu_freq_min_hz, Some(1_280_000_000));
        assert_eq!(info.cpu_freq_max_hz, Some(1_600_000_000));
    }

    #[test]
    fn parse_fdt_reports_no_freq_range_without_opp() {
        let blob = build_qemu_virt_fdt();
        let info = parse_fdt(blob.as_ptr() as usize);
        assert_eq!(info.cpu_freq_min_hz, None);
        assert_eq!(info.cpu_freq_max_hz, None);
    }
}
