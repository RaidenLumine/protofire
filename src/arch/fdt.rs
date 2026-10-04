//! src/arch/fdt.rs
//!
//! Minimal Flattened Device Tree parser for platform discovery.
//!
//! The platforms that hand a blob over are AArch64 and RISC-V: QEMU passes the
//! device tree address in a register on boot, and this module parses just
//! enough of it to discover the interrupt controller, UART, VirtIO MMIO, and
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

use crate::kernel::sync::SpinLock;

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
    /// GICv3 redistributor base address (from FDT GICv3 node, second reg
    /// entry).
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
    /// RISC-V AIA IMSIC group base address (first hart's IMSIC file),
    /// discovered from a `riscv,imsic` node's `reg` property.
    pub imsic_base: Option<usize>,
    /// PCIe ECAM (MMCONFIG) base address, discovered from
    /// `compatible = "pci-host-ecam-generic"`.
    pub ecam_base: Option<usize>,
    /// The memory window a PCI host bridge's `ranges` describes: where a
    /// device's BARs may be given addresses.  Zero-sized and absent when the
    /// machine describes none.
    pub pcie_mmio_base: Option<usize>,
    /// How large that window is.
    pub pcie_mmio_size: Option<usize>,
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
    /// Nominal CPU clock rate in Hz, discovered by following a CPU node's
    /// `clocks` phandle to a `fixed-clock` / `fixed-factor-clock` controller.
    pub cpu_clock_rate_hz: Option<u64>,
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
            imsic_base: None,
            ecam_base: None,
            pcie_mmio_base: None,
            pcie_mmio_size: None,
            ecam_start_bus: None,
            ecam_end_bus: None,
            has_sstc: false,
            cpu_count: 0,
            memory_base: None,
            memory_size: None,
            cpu_freq_min_hz: None,
            cpu_freq_max_hz: None,
            cpu_clock_rate_hz: None,
        }
    }
}

// ---------------------------------------------------------------------------
// The parser (device-tree machines only)
// ---------------------------------------------------------------------------

/// The parser is the two device-tree architectures' boot format, and the host
/// tests' synthetic blobs.  A machine with no tree compiles the interface
/// below and nothing else, which is the same thing it means: the answers stay
/// empty.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
mod parse;

/// The CPU frequency driver the device tree describes.
pub mod cpufreq;

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

/// Parse the device-tree blob handed over by the bootloader and publish the
/// platform info for later consumers (PCIe ECAM base, IMSIC base, clock
/// rates, ...).
///
/// Called once at boot on AArch64 and RISC-V while the bootstrap mapping is
/// still active, before the runtime page tables are installed.  A null or
/// malformed blob is tolerated: `parse_fdt` yields an empty `PlatformInfo`
/// and the subsystems fall back to their hardcoded QEMU `virt` defaults.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
pub fn boot_parse_fdt(blob: usize) {
    if blob == 0 {
        return;
    }
    let info = parse::parse_fdt(blob);
    store_platform_info(info);
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

    /// Record a CPU → node mapping, node ids, and distances come from the
    /// device tree, which only the device-tree machines and the host tests
    /// parse; a machine with no tree has nothing to record.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn add_cpu(&mut self, cpu_id: u32, node_id: u8) {
        let idx = self.cpu_count as usize;
        if idx < self.cpu_to_node.len() {
            self.cpu_to_node[idx] = (cpu_id, node_id);
            self.cpu_count = (idx + 1) as u32;
        }
    }

    /// Record a memory range belonging to a node.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
    fn add_memory(&mut self, node_id: u8, base: u64, end: u64) {
        let idx = self.memory_count as usize;
        if idx < self.memory_ranges.len() {
            self.memory_ranges[idx] = (node_id, base, end);
            self.memory_count = (idx + 1) as u32;
        }
    }

    /// Set a single distance matrix entry.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", test))]
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
    use crate::kernel::topology::NodeId;
    use crate::kernel::topology::NumaNode;
    use crate::kernel::topology::MAX_NUMA_NODES;

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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
