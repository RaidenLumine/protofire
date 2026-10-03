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

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        use crate::arch::riscv64::pci;
        crate::println!("[init  ] RISC-V PCIe enumeration...");
        let _ = pci::probe_and_enumerate();
    }
}

/// Hand the claimed device interrupts to the interrupt controller.
///
/// A device's MSI-X table is programmed *through* the controller, and drivers
/// claim their devices' identities before it is up, so this is the step that
/// connects the two: the claims taken at probe time are programmed here.  See
/// [`crate::arch::riscv64::pci::program_device_msix`] for what it does and why
/// it re-walks rather than carrying the device list across the boot.
pub(crate) fn program_device_msix() {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let _ = crate::arch::riscv64::pci::program_device_msix();
    }
}

/// A PCIe function's registers, as this platform can reach them.
#[cfg(target_os = "none")]
pub(crate) struct PciRegisterWindow {
    /// Vendor and device of the function the window belongs to.
    pub vendor_id: u16,
    pub device_id: u16,
    /// The address at which the kernel can read the BAR that holds the
    /// function's modern (1.0) registers, and how large that BAR is.
    pub bar_address: usize,
    pub bar_size: u64,
    /// Where the function sits on its bus, which is what its interrupts are
    /// claimed through: a driver claims them with [`pci_claim_msix`], and the
    /// platform programs them onto this function later.
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    pub function: PciFunctionAddress,
}

/// A PCIe function, as the machine that enumerated it addresses it.
///
/// The window a driver reads its registers through says nothing about where the
/// function is, and claiming its interrupts needs both: the identity range a
/// claim takes is what the platform programs *into the function's* MSI-X table.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[derive(Clone, Copy)]
pub(crate) struct PciFunctionAddress {
    /// The configuration-space window the function is reached through.
    pub region: crate::arch::pci::EcamRegion,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// Find the first PCIe function of a vendor/class, and the BAR its registers
/// live in.
///
/// The device-tree machines differ in exactly one thing here: AArch64's device
/// window sits above the range its page tables map, so a BAR has to be reached
/// through an alias, and riscv64's is inside the identity map already.
/// Everything else — walking the ECAM window, assigning BAR addresses, picking
/// the largest prefetchable MMIO BAR — is the same work, and it belongs to the
/// architecture rather than to each driver, which is why a driver asks for a
/// *window* and does not care which machine it is on.
///
/// Returns `None` on a machine that describes no window, or has none of this
/// vendor and class.
#[cfg(target_os = "none")]
pub(crate) fn pci_register_window(
    vendor_id: u16,
    class_code: u8,
    subclass: u8,
) -> Option<PciRegisterWindow> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        use crate::arch::aarch64::mmu::map_device_mmio_at;
        use crate::arch::aarch64::pci;

        let probe = pci::probe_and_enumerate()?;
        let (dev, bar) = find_virtio_function(&probe.devices, vendor_id, class_code, subclass)?;
        pci::pci_enable_memory_and_bus_master(&probe.region, dev.bus, dev.device, dev.function);

        // The fixed address this platform reserves for device windows, above
        // the ECAM alias so the two cannot overlap.
        const BAR_VA: usize = 0x2_0040_0000;
        // SAFETY: the BAR is a live MMIO range the enumeration decoded, and
        // `BAR_VA` is that reserved address.
        unsafe { map_device_mmio_at(BAR_VA, bar.base_address, bar.size as usize)? };
        Some(PciRegisterWindow {
            vendor_id: dev.vendor_id,
            device_id: dev.device_id,
            bar_address: BAR_VA,
            bar_size: bar.size,
        })
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        use crate::arch::riscv64::pci;

        let probe = pci::probe_and_enumerate()?;
        let (dev, bar) = find_virtio_function(&probe.devices, vendor_id, class_code, subclass)?;
        pci::pci_enable_memory_and_bus_master(&probe.region, dev.bus, dev.device, dev.function);

        Some(PciRegisterWindow {
            vendor_id: dev.vendor_id,
            device_id: dev.device_id,
            // This machine's device window is identity-mapped, so the address
            // the resource pass assigned is the address the kernel reads.
            bar_address: bar.base_address as usize,
            bar_size: bar.size,
            function: PciFunctionAddress {
                region: probe.region,
                bus: dev.bus,
                device: dev.device,
                function: dev.function,
            },
        })
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    {
        let _ = (vendor_id, class_code, subclass);
        None
    }
}

/// A driver's handle on the interrupts it claimed from a device.
///
/// It exists on every machine, because the completion path asks it the same
/// question everywhere — "can this device signal yet?" — and the answer on a
/// machine whose devices signal through a line nobody waits on is "no", which
/// is the same answer as a claim the platform has not programmed yet.  That is
/// what lets a driver keep one completion path instead of one per machine.
#[cfg(target_os = "none")]
pub(crate) struct DeviceInterrupts {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    claim: crate::arch::riscv64::pci::MsixClaim,
}

#[cfg(target_os = "none")]
impl DeviceInterrupts {
    /// Whether the device's table has been programmed and let through.
    pub fn is_armed(&self) -> bool {
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            self.claim.is_armed()
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        {
            false
        }
    }

    /// The first interrupt identity the device's table delivers.
    ///
    /// Zero when the machine gave the device no identity at all — identity 0 is
    /// not an interrupt, so it can stand for "none".
    pub fn first_irq(&self) -> u32 {
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            self.claim.first_irq()
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        {
            0
        }
    }
}

/// Claim the window's device interrupts for `handler`.
///
/// This is the driver's half of the contract: the identities the device's MSI-X
/// table will deliver are allocated and `handler` is registered for each.  It
/// works at probe time — before the interrupt controller is initialised —
/// because a registration is a table entry, not a hardware access.  The
/// platform keeps the claim and programs the table with those identities later,
/// at [`program_device_msix`], which is also when the device is first allowed
/// to signal.
///
/// Answers `None` when there is no unclaimed table to give: a machine with no
/// MSI receiver, a device with no MSI-X, or one somebody has already taken.
#[cfg(target_os = "none")]
pub(crate) fn pci_claim_msix(
    window: &PciRegisterWindow,
    handler: impl Fn(u32) + Send + Sync + 'static,
) -> Option<DeviceInterrupts> {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        use alloc::sync::Arc;

        let function = window.function;
        let handler: crate::arch::riscv64::aia_imsic::IrqHandler = Arc::new(handler);
        let claim = crate::arch::riscv64::pci::claim_msix(
            &function.region,
            function.bus,
            function.device,
            function.function,
            handler,
        )
        .ok()?;
        crate::arch::riscv64::pci::defer_msix_arming(claim.clone());
        Some(DeviceInterrupts { claim })
    }

    #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
    {
        let _ = (window, handler);
        None
    }
}

/// The device and the largest prefetchable MMIO BAR of the first function that
/// matches.
///
/// The modern transport spreads its register areas over the biggest BAR —
/// BAR4 on QEMU's transitional `virtio-net-pci`, which also carries the smaller
/// one the legacy layout used — so picking the largest prefetchable one is
/// picking the modern interface's.
#[cfg(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
fn find_virtio_function(
    devices: &[crate::arch::pci::PciDeviceInfo],
    vendor_id: u16,
    class_code: u8,
    subclass: u8,
) -> Option<(
    &crate::arch::pci::PciDeviceInfo,
    &crate::arch::pci::PciBarInfo,
)> {
    for dev in devices {
        if dev.vendor_id != vendor_id || dev.class_code != class_code || dev.subclass != subclass {
            continue;
        }
        let bar = dev
            .bars
            .iter()
            .filter(|bar| bar.is_mmio && bar.base_address != 0)
            .max_by_key(|bar| (bar.is_prefetchable, bar.size))?;
        return Some((dev, bar));
    }
    None
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

// `describe_user_slots` describes a bare-metal machine's prepared slots, so it
// is compiled where such slots exist.  `demo_user_programs` is the machine's
// list of prototype programs, and it is compiled wherever the demo *tree* is
// (`any(feature = "demo-disk", test, not(target_os = "none"))`): a host that
// builds the demo disk writes the same list into `/system/rc.d` that the
// machine reads back out of it, and the two have to be one list.
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

/// The embedded user programs this machine's prototype can run, and which of
/// them the supervisor should restart.
///
/// The list is the machine's because the user-mode prototypes are: x86_64 runs
/// the whole demo set, aarch64 its EL0 pair, riscv64 a single U-mode program.
/// Exactly one entry asks to be restarted, which is what keeps the supervision
/// loop — detect, restart, exhaust the budget, abandon — on the path every
/// stock boot takes.
#[cfg(any(feature = "demo-disk", test))]
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
