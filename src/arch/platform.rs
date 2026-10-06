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
/// connects the two: the claims taken at probe time are programmed here.  The
/// machine's own half is what differs — RISC-V maps a device's table onto an
/// IMSIC file, AArch64 maps it through an ITS — and what each of them does is
/// documented where it lives
/// ([`crate::arch::riscv64::pci::program_device_msix`],
/// [`crate::arch::aarch64::its::program_device_msix`]).
pub(crate) fn program_device_msix() {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let _ = crate::arch::aarch64::its::program_device_msix();
    }
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let _ = crate::arch::riscv64::pci::program_device_msix();
    }
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let _ = crate::arch::x86_64::msi::program_device_msix();
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
    #[cfg(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    ))]
    pub function: PciFunctionAddress,
    /// The same fact on x86_64, where configuration space is reached through
    /// port I/O rather than an ECAM window: the bus address *is* the function,
    /// and claiming its interrupts goes through that address directly.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub function: crate::arch::x86_64::pci::PciAddress,
}

/// A PCIe function, as the machine that enumerated it addresses it.
///
/// The window a driver reads its registers through says nothing about where the
/// function is, and claiming its interrupts needs both: the identity range a
/// claim takes is what the platform programs *into the function's* MSI-X table.
#[cfg(any(
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "riscv64", target_os = "none")
))]
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

        // A slot of the platform's BAR-alias window, one per registered
        // window: the alias cannot be one fixed address, because the second
        // device to register would map its BAR over the first driver's
        // registers and both would read the wrong device.
        let bar_va = crate::arch::aarch64::mmu::reserve_device_bar_alias(bar.size as usize)?;
        // SAFETY: the BAR is a live MMIO range the enumeration decoded, and
        // `bar_va` is a slot this platform reserved for exactly this mapping.
        unsafe { map_device_mmio_at(bar_va, bar.base_address, bar.size as usize)? };
        Some(PciRegisterWindow {
            vendor_id: dev.vendor_id,
            device_id: dev.device_id,
            bar_address: bar_va,
            bar_size: bar.size,
            function: PciFunctionAddress {
                region: probe.region,
                bus: dev.bus,
                device: dev.device,
                function: dev.function,
            },
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

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use crate::arch::x86_64::pci;

        let devices = pci::pci_enumerate_buses();
        let (device, bar) = find_virtio_function(&devices, vendor_id, class_code, subclass)?;
        let address = pci::PciAddress::new(device.bus, device.device, device.function);

        // Enable Memory Space and Bus Master: the modern transport's registers
        // live in a BAR, and the device reaches the rings by bus-mastering.
        // SAFETY: the command register of a function this scan enumerated,
        // inside its own configuration space.
        let command = unsafe { pci::pci_config_read_u16(address, pci::COMMAND) };
        // SAFETY: as above — writing that register to enable the two spaces the
        // transport and its descriptors need.
        unsafe {
            pci::pci_config_write_u16(address, pci::COMMAND, command | (1 << 1) | (1 << 2));
        }

        // SAFETY: `bar` is a live MMIO range the enumeration decoded.
        let mapped =
            unsafe { crate::arch::mmu::map_device_mmio(bar.base_address, bar.size as usize) }?;
        Some(PciRegisterWindow {
            vendor_id: device.vendor_id,
            device_id: device.device_id,
            bar_address: mapped as usize,
            bar_size: bar.size,
            function: address,
        })
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none")
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
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    claim: crate::arch::aarch64::its::MsixClaim,
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    claim: crate::arch::x86_64::msi::MsixClaim,
}

#[cfg(target_os = "none")]
impl DeviceInterrupts {
    /// Whether the device's table has been programmed and let through.
    pub fn is_armed(&self) -> bool {
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            self.claim.is_armed()
        }
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            self.claim.is_armed()
        }
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            self.claim.is_armed()
        }
        #[cfg(not(any(
            all(target_arch = "riscv64", target_os = "none"),
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none")
        )))]
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
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            self.claim.first_irq()
        }
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            self.claim.first_irq()
        }
        #[cfg(not(any(
            all(target_arch = "riscv64", target_os = "none"),
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "x86_64", target_os = "none")
        )))]
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
    named: &[(u16, crate::arch::irq_handlers::IrqHandler)],
    fallback: &crate::arch::irq_handlers::IrqHandler,
) -> Option<DeviceInterrupts> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let function = window.function;
        let claim = crate::arch::aarch64::its::claim_msix(
            &function.region,
            function.bus,
            function.device,
            function.function,
            named,
            fallback,
        )
        .ok()?;
        crate::arch::aarch64::its::defer_msix_arming(claim.clone());
        Some(DeviceInterrupts { claim })
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    {
        let function = window.function;
        let claim = crate::arch::riscv64::pci::claim_msix(
            &function.region,
            function.bus,
            function.device,
            function.function,
            named,
            fallback,
        )
        .ok()?;
        crate::arch::riscv64::pci::defer_msix_arming(claim.clone());
        Some(DeviceInterrupts { claim })
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        // SAFETY: the window names a function this machine enumerated, which is
        // the contract `claim_msix` asks for.
        let claim =
            unsafe { crate::arch::x86_64::msi::claim_msix(window.function, named, fallback) }
                .ok()?;
        crate::arch::x86_64::msi::defer_msix_arming(claim.clone());
        Some(DeviceInterrupts { claim })
    }

    #[cfg(not(any(
        all(target_arch = "riscv64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "x86_64", target_os = "none")
    )))]
    {
        let _ = (window, named, fallback);
        None
    }
}

/// Claim the interrupts of a function the caller has already found.
///
/// [`pci_claim_msix`] is for a driver that asks the platform which device it
/// should drive; this is for one that has done its own discovery and knows the
/// function it is holding — an xHCI controller, whose class has no single
/// vendor to match on.  Everything after the discovery is the same: the
/// identities are claimed here, the table is programmed by
/// [`program_device_msix`] once the machine can receive, and the caller's
/// completion path waits on the interrupt only after that.
///
/// Answers `None` on a machine whose devices do not signal this way, which
/// leaves the caller on whatever path it had.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn claim_function_interrupts(
    address: crate::arch::x86_64::pci::PciAddress,
    named: &[(u16, crate::arch::irq_handlers::IrqHandler)],
    fallback: &crate::arch::irq_handlers::IrqHandler,
) -> Option<DeviceInterrupts> {
    // SAFETY: the caller says `address` names a function this machine
    // enumerated, which is the contract `claim_msix` asks for.
    let claim = match unsafe { crate::arch::x86_64::msi::claim_msix(address, named, fallback) } {
        Ok(claim) => claim,
        Err(error) => {
            // Say why, because the alternative is a device that is silently on
            // its polling path: a function with no MSI-X capability, one whose
            // vector space is taken, and one whose table cannot be mapped all
            // answer the same way from the outside.
            crate::println!(
                "[msix  ] {:02x}:{:02x}.{} not claimed ({:?})",
                address.bus,
                address.device,
                address.function,
                error
            );
            return None;
        }
    };
    crate::arch::x86_64::msi::defer_msix_arming(claim.clone());
    Some(DeviceInterrupts { claim })
}

/// The handler each identity of a device's MSI-X table is registered for.
///
/// `named` holds the entries the driver uses for itself — one per queue, in
/// the shape the transport numbers them.  Every other entry the table can
/// deliver gets `fallback`, because an identity the device can signal and
/// nobody owns is counted as spurious, which is a worse answer than a wakeup
/// that turns out to be for another queue.
///
/// Answers `None` when a named vector is outside the device's table — a driver
/// asking for an entry the device does not have.  The caller refuses the claim,
/// so the device stays on its polling path instead of losing a queue's
/// interrupt silently.
// Every configuration that compiles an architecture's MSI-X claim needs this,
// including the aarch64 host target `make check` type-checks.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    all(target_arch = "x86_64", target_os = "none")
))]
pub(crate) fn msix_handlers_for(
    count: u32,
    named: &[(u16, crate::arch::irq_handlers::IrqHandler)],
    fallback: &crate::arch::irq_handlers::IrqHandler,
) -> Option<alloc::vec::Vec<crate::arch::irq_handlers::IrqHandler>> {
    if named.iter().any(|(vector, _)| (*vector as u32) >= count) {
        return None;
    }
    let mut handlers = alloc::vec::Vec::with_capacity(count as usize);
    for index in 0..count {
        let handler = named
            .iter()
            .find(|(vector, _)| *vector as u32 == index)
            .map(|(_, handler)| handler.clone())
            .unwrap_or_else(|| fallback.clone());
        handlers.push(handler);
    }
    Some(handlers)
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
    all(target_arch = "riscv64", target_os = "none"),
    all(target_arch = "x86_64", target_os = "none")
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
