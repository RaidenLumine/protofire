//! src/arch/platform.rs
//!
//! What the machine is asked during boot, and what it does to itself.
//!
//! The boot *sequence* is the kernel's: the order of these steps is a
//! correctness constraint, so it stays in `Kernel::init` where it can be read
//! as one list.  What each step does is the machine's — saving the state a
//! secondary CPU will restore, reading the table that describes the platform,
//! enumerating a bus, bringing the other CPUs up, and assembling the NUMA
//! topology from whichever table this machine keeps it in.  None of it names
//! an architecture outside this file.

use crate::kernel::topology::Topology;

/// Save the machine state that must be captured before the runtime page
/// tables replace the bootstrap mapping.
///
/// x86_64 saves the boot CR3 and reads ACPI for the CPU list and the NUMA
/// tables, because after the switch those physical addresses are no longer
/// reachable through the identity map.  aarch64 saves the MMU configuration
/// and the vector base, which a secondary CPU restores verbatim.  riscv64
/// takes its configuration from the device tree, so it has nothing to save
/// here.
pub(crate) fn capture_early_state() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        crate::arch::x86_64::smp::save_boot_cr3();
        let handoff = crate::arch::boot::handoff_address();
        let aps = crate::arch::x86_64::acpi::discover_aps(handoff);
        crate::arch::x86_64::acpi::store_early_aps(aps);
        // Discover NUMA topology from ACPI SRAT/SLIT (before page-table
        // switch, while the identity map still covers physical memory).
        crate::arch::x86_64::acpi::discover_numa(handoff);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // Save the boot MMU configuration (TTBR0/TTBR1/TCR/MAIR/SCTLR) and
        // VBAR before we switch to runtime kernel page tables.  AP secondary
        // CPUs will restore this exact configuration.
        crate::arch::aarch64::smp::save_boot_mmu_config();
        crate::arch::aarch64::smp::save_vbar_addr();
        crate::println!("[init  ] aarch64: saved boot MMU config and VBAR");
    }
}

/// Read the platform description the bootloader handed over.
///
/// AArch64 and RISC-V are handed a device tree in a register; parsing it here,
/// before the runtime page tables replace the bootstrap mapping, is what makes
/// the platform info (PCIe ECAM base, IMSIC base, clock rates) available to
/// enumeration and driver init.  A null or malformed blob is tolerated: the
/// machine keeps its fallbacks.
pub(crate) fn describe_platform() {
    #[cfg(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    ))]
    {
        let blob = crate::arch::boot::handoff_address();
        crate::arch::fdt::boot_parse_fdt(blob);
    }
}

/// Enumerate the machine's buses and log what is attached.
///
/// x86_64 walks the PCI bus it discovered through ACPI; aarch64 discovers and
/// maps its ECAM region through a low-VA alias and logs what answers there.
/// Per-driver probing scans the same bus during driver init, so running the
/// generic enumeration first is idempotent: re-mapping the region is a no-op
/// and re-enumeration only re-reads config space.
pub(crate) fn enumerate_buses() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use crate::arch::x86_64::pci;
        crate::println!("[init  ] PCI/PCIe enumeration...");
        let devices = pci::pci_enumerate_buses();
        pci::log_pci_devices(&devices);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        use crate::arch::aarch64::pci;
        crate::println!("[init  ] AArch64 PCIe enumeration...");
        let _ = pci::probe_and_enumerate();
    }
}

/// Bring up every CPU the machine reported that is not already running.
pub(crate) fn bring_up_secondary_cpus() {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        if let Some(aps) = crate::arch::x86_64::acpi::take_early_aps() {
            if !aps.is_empty() {
                crate::println!("[init  ] SMP: bringing up {} AP(s)...", aps.len());
                crate::arch::x86_64::smp::bring_up_aps(&aps);
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        crate::arch::aarch64::smp::bring_up_aps();
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        crate::arch::riscv64::smp::bring_up_aps();
    }
}

/// The topology this machine describes, if it describes one.
///
/// x86_64 reads ACPI SRAT/SLIT; the device-tree machines read their NUMA
/// nodes.  `None` means the machine described none, and the caller builds the
/// single-node topology instead.
pub(crate) fn numa_topology() -> Option<Topology> {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let numa = crate::arch::x86_64::acpi::take_early_numa()?;
        let topo = topology_from_srat(&numa);
        let node_count = topo.nodes.len();
        if node_count > 1 {
            crate::println!("[init  ] NUMA: {} nodes from ACPI SRAT/SLIT", node_count);
        } else {
            crate::println!("[init  ] NUMA: single node from ACPI SRAT");
        }
        Some(topo)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        let topo = crate::arch::fdt::build_fdt_numa_topology()?;
        let node_count = topo.nodes.len();
        if node_count > 1 {
            crate::println!("[init  ] NUMA: {} nodes from FDT", node_count);
        } else {
            crate::println!("[init  ] NUMA: single node from FDT");
        }
        Some(topo)
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        None
    }
}

/// How many CPUs this machine reports before the others are up.
///
/// The device-tree machines can count their `/cpus` nodes; everywhere else the
/// SMP layer is the only one that knows, and before AP bring-up that answer is
/// one.
pub(crate) fn reported_cpu_count() -> u32 {
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        crate::arch::fdt::cpu_count().max(1)
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    {
        crate::kernel::smp::online_cpu_count().max(1)
    }
}

/// Build a [`Topology`] from the ACPI SRAT/SLIT tables x86_64 was handed.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn topology_from_srat(numa: &crate::arch::x86_64::acpi::EarlyNumaData) -> Topology {
    use crate::kernel::topology::NodeId;
    use crate::kernel::topology::NumaNode;
    use crate::kernel::topology::MAX_NUMA_NODES;
    use crate::kernel::topology::NUMA_NODE_NONE;

    // ── Build cpu_to_node mapping ──
    let cpu_count = numa.cpu_apic_ids.len();
    let mut cpu_to_node: alloc::vec::Vec<NodeId> = alloc::vec![0u8; cpu_count];

    for &(logical_id, apic_id) in &numa.cpu_apic_ids {
        let idx = logical_id as usize;
        if idx >= cpu_count {
            continue;
        }
        let mut node_id: NodeId = 0;
        // Search LAPIC affinities first.
        for aff in &numa.cpu_affinities {
            if aff.enabled && aff.apic_id == apic_id {
                node_id = aff.node_id;
                break;
            }
        }
        // Fall back to x2APIC affinities.
        if node_id == 0 && !numa.x2apic_affinities.is_empty() {
            for aff in &numa.x2apic_affinities {
                if aff.enabled && aff.x2apic_id == apic_id as u32 {
                    node_id = aff.node_id as u8;
                    break;
                }
            }
        }
        cpu_to_node[idx] = node_id;
    }

    // ── Collect unique node IDs ──
    let mut node_ids: [NodeId; MAX_NUMA_NODES] = [NUMA_NODE_NONE; MAX_NUMA_NODES];
    let mut unique_count = 0usize;
    for &nid in &cpu_to_node {
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

    // ── Build NumaNode list ──
    let mut nodes: alloc::vec::Vec<NumaNode> = alloc::vec::Vec::with_capacity(unique_count);
    for nid in node_ids.iter().take(unique_count) {
        let nid = *nid;
        let mut cpus: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        for (logical_id, _apic_id) in &numa.cpu_apic_ids {
            if *logical_id < cpu_count as u32 && cpu_to_node[*logical_id as usize] == nid {
                cpus.push(*logical_id);
            }
        }
        nodes.push(NumaNode {
            id: nid,
            cpu_ids: cpus,
            memory_ranges: alloc::vec::Vec::new(),
        });
    }

    // ── Add memory ranges from SRAT ──
    for aff in &numa.memory_affinities {
        if !aff.enabled {
            continue;
        }
        let mem_node_id = aff.node_id as u8;
        let mut found = false;
        for node in &mut nodes {
            if node.id == mem_node_id {
                node.memory_ranges
                    .push((aff.base_addr, aff.base_addr + aff.length));
                found = true;
                break;
            }
        }
        if !found && nodes.len() < MAX_NUMA_NODES {
            nodes.push(NumaNode {
                id: mem_node_id,
                cpu_ids: alloc::vec::Vec::new(),
                memory_ranges: alloc::vec![(aff.base_addr, aff.base_addr + aff.length)],
            });
        }
    }

    // ── Distance matrix from SLIT ──
    let distance_matrix = numa.slit_matrix.clone().unwrap_or_default();

    Topology {
        nodes,
        cpu_to_node,
        distance_matrix,
    }
}

// Both of these describe the demo distribution, which only exists on a bare
// metal build that asked for it (`demo-disk`) or in the test build that builds
// the same thing; everywhere else the kernel spawns no embedded user programs
// and neither of these is compiled.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
/// Describe the user slots this machine prepared, where it prepares any.
///
/// The device-tree machines preallocate fixed slots for their EL0/U-mode
/// prototypes and say so here; x86_64 builds an address space per process and
/// has nothing to describe.
pub(crate) fn describe_user_slots() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        use crate::arch::mmu;
        if let Some(region) = mmu::demo_user_slot_layout(0) {
            crate::println!(
                "[user  ] prepared aarch64 EL0 demo slots={} entry={:#018x} stack={:#018x} exception-stack={:#018x} region={:#018x}..{:#018x}",
                mmu::demo_user_slot_count(),
                region.entry_point,
                region.stack_top,
                region.exception_stack_top,
                region.region_start,
                region.region_start + region.region_length
            );
        }
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        use crate::arch::mmu;
        if let Some(region) = mmu::demo_user_slot_layout(0) {
            crate::println!(
                "[user  ] prepared riscv64 U-mode demo slots={} entry={:#018x} stack={:#018x} exception-stack={:#018x} region={:#018x}..{:#018x}",
                mmu::demo_user_slot_count(),
                region.entry_point,
                region.stack_top,
                region.exception_stack_top,
                region.region_start,
                region.region_start + region.region_length
            );
        }
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        crate::println!("[user  ] demo user programs are unavailable on this architecture");
    }
}

// Both of these describe the demo distribution, which only exists on a bare
// metal build that asked for it (`demo-disk`) or in the test build that builds
// the same thing; everywhere else the kernel spawns no embedded user programs
// and neither of these is compiled.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
/// The embedded user programs this machine's prototype can run, and which of
/// them the supervisor should restart.
///
/// The list is the machine's because the user-mode prototypes are: x86_64 runs
/// the whole demo set, aarch64 its EL0 pair, riscv64 a single U-mode program.
/// Exactly one entry asks to be restarted, which is what keeps the supervision
/// loop — detect, restart, exhaust the budget, abandon — on the path every
/// stock boot takes.
pub(crate) fn demo_user_programs() -> &'static [(&'static str, bool)] {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::user::program;
        &[
            (program::DEMO_RUST_IO_CURRENT_PATH, false),
            (program::DEMO_CURRENT_PATH, false),
            (program::DEMO_FAULT_CURRENT_PATH, true),
            (program::DEMO_INVALID_OPCODE_CURRENT_PATH, false),
            (program::DEMO_GENERAL_PROTECTION_CURRENT_PATH, false),
            (program::DEMO_ONE_SHOT_PAGE_FAULT_CURRENT_PATH, false),
            (program::DEMO_NESTED_PAGE_FAULT_CURRENT_PATH, false),
        ]
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::user::program;
        &[
            (program::DEMO_CURRENT_PATH, false),
            (program::DEMO_RUST_CURRENT_PATH, false),
        ]
    }

    #[cfg(target_arch = "riscv64")]
    {
        use crate::user::program;
        &[(program::DEMO_CURRENT_PATH, false)]
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        &[]
    }
}
