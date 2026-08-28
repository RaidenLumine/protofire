//! src/kernel/mod.rs
//!
//! Kernel bootstrap entry that wires memory, drivers, filesystem, scheduler,
//! and syscall table.

pub mod audit;
pub mod boot_report;
pub mod compression;
pub mod config;
pub mod console;
pub mod crypto;
pub mod device;
pub mod drivers;
pub mod fs;
pub mod io;
pub mod irq_balance;
pub mod irq_stats;
pub mod kernel_log;
pub mod memory;
pub mod network;
pub mod nmi;
pub mod oom;
pub mod percpu;
pub mod power;
pub mod process;
pub mod random;
pub mod scheduler;
// Service-definition parsing (`/system/rc.d/*.toml`) is only exercised by the
// demo distribution's embedded default services; a pure kernel boot spawns
// the distribution's `/system/init.elf` directly and never reads rc.d.
#[cfg(any(feature = "demo-disk", test))]
pub mod service;
pub mod shm;
pub mod smp;
pub mod softirq;
pub mod sync;
pub mod syscall;
pub mod topology;
pub mod user;

use crate::arch;
use crate::println;
#[cfg(any(test, target_os = "none"))]
use crate::user::program;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use crate::user::syscall::UserSyscall;

use drivers::DriverManager;
use fs::FileSystem;
use memory::MemoryManager;
use process::Scheduler;
#[cfg(target_os = "none")]
use process::SecurityToken;
use sync::Mutex;

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const DEMO_README_SAMPLE_PATH: &str = "/system/runtime/README.txt";
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const DEMO_README_SAMPLE_BYTES: usize = 24;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const DEMO_WORKER_STEPS: usize = 3;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const DEMO_WORKER_SLEEP_TICKS: u64 = 6;

/// Default init program path on the boot filesystem.
///
/// The kernel attempts to load and spawn the ELF at this path after
/// subsystem initialisation.  The distribution (protofire-os) is responsible
/// for placing a suitable init program here when building the boot disk.
const DEFAULT_INIT_PATH: &str = "/system/init.elf";

// ── Volume recovery summary ────────────────────────────────────────────

/// Accumulated volume recovery counters captured during `recover_volumes()`
/// and queryable at runtime via the `SystemHealth` syscall.
#[derive(Debug, Clone, Copy, Default)]
pub struct VolumeRecoverySummary {
    pub volumes_checked: u64,
    pub repairs_applied: u64,
    pub issues_detected: u64,
    pub orphan_data_blocks: u64,
    pub checksum_failures: u64,
    pub staging_orphans_cleaned: u64,
    pub orphan_blocks_cleaned: u64,
    pub interrupted_commits: u64,
}

static VOLUME_RECOVERY_SUMMARY: Mutex<Option<VolumeRecoverySummary>> = Mutex::new(None);

/// Store the volume recovery summary after boot-time volume checks complete.
fn install_volume_recovery_summary(summary: VolumeRecoverySummary) {
    let mut slot = VOLUME_RECOVERY_SUMMARY.lock();
    *slot = Some(summary);
}

/// Return a copy of the volume recovery summary, or `Default` if no recovery
/// has run yet (pre-boot or host build).
pub fn volume_recovery_summary() -> VolumeRecoverySummary {
    VOLUME_RECOVERY_SUMMARY.lock().unwrap_or_default()
}

pub struct Kernel {
    memory: MemoryManager,
    scheduler: Scheduler,
    fs: Mutex<FileSystem>,
    drivers: DriverManager,
    syscall_table: syscall::Table,
    initialized: bool,
}

impl Drop for Kernel {
    fn drop(&mut self) {
        fs::uninstall_global(&self.fs);
        // Clear the thread-local scheduler pointer so that subsequent tests
        // on the same thread do not see a dangling pointer.  `syscall::Table`
        // already clears its global via its own Drop impl.
        #[cfg(test)]
        Scheduler::clear_thread_local_scheduler();
    }
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

impl Kernel {
    pub fn new() -> Self {
        Self {
            memory: MemoryManager::new(),
            scheduler: Scheduler::new(),
            fs: Mutex::new(FileSystem::new()),
            drivers: DriverManager::new(),
            syscall_table: syscall::Table::new(),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        if self.initialized {
            return;
        }

        let mut boot = boot_report::BootReport::new();
        let tick = || self.scheduler.current_tick();

        let t0 = tick();
        self.memory.init();
        // SAFETY: the kernel owns the memory manager for the lifetime of the
        // running system, and `MemoryManager::drop` clears the global slot
        // before host-side teardown releases the storage.
        unsafe {
            memory::install_global_unchecked(&self.memory);
        }

        // ── SMP AP discovery (must run before prepare_arch_paging) ──
        // The bootstrap identity map is still active at this point, so
        // ACPI tables at arbitrary physical addresses are readable.
        // Also save the boot CR3 before we switch page tables — the AP
        // trampoline needs the bootstrap identity map (first 1 GiB).
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            crate::kernel::smp::save_boot_cr3();
            let handoff = crate::arch::boot::handoff_address();
            let aps = crate::kernel::smp::discover_aps(handoff);
            crate::kernel::smp::store_early_aps(aps);
            // Discover NUMA topology from ACPI SRAT/SLIT (before page-table
            // switch, while the identity map still covers physical memory).
            crate::kernel::smp::discover_numa(handoff);
        }
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            // Save the boot MMU configuration (TTBR0/TTBR1/TCR/MAIR/SCTLR)
            // and VBAR before we switch to runtime kernel page tables.
            // AP secondary CPUs will restore this exact configuration.
            crate::arch::aarch64::smp::save_boot_mmu_config();
            crate::arch::aarch64::smp::save_vbar_addr();
            println!("[init  ] aarch64: saved boot MMU config and VBAR");
        }

        // ── Device-tree handoff (AArch64 / RISC-V) ──
        // Parse the DTB passed by the bootloader before the runtime page
        // tables replace the bootstrap mapping, so the platform info (PCIe
        // ECAM base, IMSIC base, clock rates, ...) is available to
        // enumeration and driver init.  A null or malformed blob leaves the
        // hardcoded QEMU `virt` fallbacks in place.
        #[cfg(any(
            all(target_arch = "aarch64", target_os = "none"),
            all(target_arch = "riscv64", target_os = "none")
        ))]
        {
            let blob = crate::arch::boot::handoff_address();
            crate::arch::fdt::boot_parse_fdt(blob);
        }

        self.prepare_arch_paging();

        let t1 = tick();
        boot.record_subsystem(
            "memory",
            crate::abi::diagnostic::SUBSYSTEM_STATUS_OK,
            t0,
            t1,
        );

        console::init_global();
        let t2 = tick();
        boot.record_subsystem(
            "console",
            crate::abi::diagnostic::SUBSYSTEM_STATUS_OK,
            t1,
            t2,
        );

        self.drivers.init();
        let boot_disk = self.drivers.boot_disk();
        self.fs.lock().init_with_boot_disk(boot_disk);
        let t3 = tick();
        boot.record_subsystem(
            "drivers+fs",
            crate::abi::diagnostic::SUBSYSTEM_STATUS_OK,
            t2,
            t3,
        );

        // ── Swap area initialisation ──
        // Scan registered block devices for a swap partition or device and
        // initialise the swap subsystem if one is found.  This must happen
        // after filesystem init (which registers block devices) and before
        // PCI enumeration so that swap can use any block device.
        #[cfg(target_os = "none")]
        self.maybe_init_swap();

        // ── PCI/PCIe enumeration ──
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            use crate::arch::x86_64::pci;
            crate::println!("[init  ] PCI/PCIe enumeration...");
            let devices = pci::pci_enumerate_buses();
            pci::log_pci_devices(&devices);
        }
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            // PCIe enumeration on aarch64 discovers and maps the ECAM region
            // through a low-VA alias and logs attached devices.  Per-driver
            // probing (virtio-net) scans the same bus during driver init;
            // running the generic enumeration here is idempotent because
            // re-mapping the region is a no-op and re-enumeration only
            // re-reads config space.
            use crate::arch::aarch64::pci;
            crate::println!("[init  ] AArch64 PCIe enumeration...");
            let _ = pci::probe_and_enumerate();
        }

        // Initialize the bare-metal network stack if a VirtIO network device
        // was discovered during driver probing.  Start with a placeholder IP
        // (0.0.0.0), then run DHCP to obtain a real address.  Fall back to
        // QEMU's default guest IP (10.0.2.15) if DHCP fails.
        #[cfg(target_os = "none")]
        if let Some(net_device) = self.drivers.boot_net_device() {
            use crate::kernel::network::stack::NetworkStack;
            const DEFAULT_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
            NetworkStack::init_with_device(net_device, [0, 0, 0, 0]);
            println!("[kernel] network stack initialized");

            // Attempt DHCP address negotiation.
            let dhcp_result = crate::kernel::network::dhcp::discover_and_request();
            let assigned_ip = match dhcp_result {
                Ok(ref lease) => lease.yiaddr,
                Err(_) => DEFAULT_GUEST_IP,
            };
            if let Some(stack) = NetworkStack::global() {
                stack.set_ip(assigned_ip);
                // Wire up any DHCP-provided network configuration (DNS, gateway,
                // subnet mask).  Missing options keep the compile-time defaults
                // that were set during init_with_device.
                if let Ok(ref lease) = dhcp_result {
                    if let Some(dns) = lease.dns_server {
                        stack.set_dns_server(dns);
                    }
                    if let Some(gw) = lease.router {
                        stack.set_gateway(gw);
                    }
                    if let Some(mask) = lease.subnet_mask {
                        stack.set_subnet_mask(mask);
                    }
                    // Store the lease for future renewal.  This also records
                    // the lease-start tick and resets the state to Bound.
                    stack.set_dhcp_lease(lease.clone());
                    println!(
                        "[kernel] DHCP: assigned IP {}.{}.{}.{} dns={}.{}.{}.{} gw={}.{}.{}.{} lease={}s",
                        assigned_ip[0],
                        assigned_ip[1],
                        assigned_ip[2],
                        assigned_ip[3],
                        lease.dns_server.unwrap_or([0; 4])[0],
                        lease.dns_server.unwrap_or([0; 4])[1],
                        lease.dns_server.unwrap_or([0; 4])[2],
                        lease.dns_server.unwrap_or([0; 4])[3],
                        lease.router.unwrap_or([0; 4])[0],
                        lease.router.unwrap_or([0; 4])[1],
                        lease.router.unwrap_or([0; 4])[2],
                        lease.router.unwrap_or([0; 4])[3],
                        lease.lease_ticks / crate::kernel::network::dhcp::TICKS_PER_SECOND,
                    );
                } else {
                    println!(
                        "[kernel] DHCP: assigned IP {}.{}.{}.{} (static fallback)",
                        assigned_ip[0], assigned_ip[1], assigned_ip[2], assigned_ip[3]
                    );
                }

                // ── IPv6 SLAAC (skip during early boot) ──
                // SLAAC depends on system ticks advancing, which only
                // happens after the timer interrupt is configured later
                // in the boot sequence.  Running SLAAC here would hang.
                // TODO: defer SLAAC to post-timer-init or make it
                // non-blocking during early boot.
                crate::println!("[kernel] IPv6 SLAAC: skipped (pre-timer boot)");
            }
        }

        // SAFETY: the kernel object is created once during boot and never dropped
        // on the bare-metal execution path, so this reference remains valid.
        unsafe {
            fs::install_global_unchecked(&self.fs);
        }
        let (tx_recovered, tx_repaired) = self.recover_install_management_state();
        let (vol_checked, vol_repaired) = self.recover_volumes();
        #[cfg(any(feature = "demo-disk", test))]
        self.log_demo_storage_sample();
        boot.set_recovery_summary(tx_recovered, tx_repaired, vol_checked, vol_repaired);
        let t4 = tick();

        // ── BootReport: subsystem tracking continued ──
        use crate::abi::diagnostic::SUBSYSTEM_STATUS_OK;

        boot.record_subsystem("recovery", SUBSYSTEM_STATUS_OK, t3, t4);

        println!("[init  ] user database init...");
        {
            let fs = self.fs.lock();
            user::init_user_database(&fs);
        }

        println!("[init  ] interrupt controller init...");
        arch::interrupt_controller::init();
        println!("[init  ] timer init...");
        arch::timer::init();
        let t5 = tick();
        boot.record_subsystem("interrupts+timer", SUBSYSTEM_STATUS_OK, t4, t5);

        // ── NUMA topology initialisation ──
        self.init_numa();

        // ── Per-CPU data initialisation (x86_64 SMP) ──
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            let lapic_id = crate::arch::x86_64::apic::lapic_id();
            // LAPIC IDs fit in a byte on current hardware; the SMP layer and
            // percpu tables store them as u8.
            let lapic_id = lapic_id as u8;
            crate::kernel::smp::save_bsp_lapic_id(lapic_id);
            crate::kernel::percpu::init_bsp(
                &self.scheduler as *const Scheduler as *mut Scheduler,
                lapic_id,
                crate::arch::x86_64::gdt::bsp_tss_ptr() as *mut u8,
            );
            // Register the BSP scheduler in the static percpu-scheduler table
            // so cross-CPU operations can find it.
            unsafe {
                crate::kernel::smp::register_percpu_scheduler(
                    0,
                    &self.scheduler as *const Scheduler as *mut Scheduler,
                );
            }
            println!("[init  ] percpu BSP cpu_id=0 lapic_id={}", lapic_id);
        }

        // ── Per-CPU data initialisation (AArch64 SMP) ──
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            use alloc::boxed::Box;
            // Allocate PerCpuData for the BSP and point TPIDR_EL1 at it.
            // This enables per-CPU access paths on AArch64.
            let percpu = Box::new(crate::kernel::percpu::PerCpuData::zeroed());
            let percpu_ptr = Box::into_raw(percpu);
            unsafe {
                (*percpu_ptr).cpu_id = 0; // BSP
                (*percpu_ptr).scheduler = &self.scheduler as *const Scheduler as *mut Scheduler;
            }
            crate::kernel::percpu::aarch64_set_tpidr_el1(percpu_ptr as u64);
            // Register the BSP scheduler in the per-CPU table so cross-CPU
            // operations (wake, reschedule IPI) can find it.
            crate::kernel::smp::register_percpu_scheduler(
                0,
                &self.scheduler as *const Scheduler as *mut Scheduler,
            );
            println!("[init  ] aarch64: BSP percpu cpu_id=0 TPIDR_EL1 set");
        }

        // ── Per-CPU data initialisation (RISC-V SMP) ──
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            use alloc::boxed::Box;
            // Allocate PerCpuData for the BSP and point tp (x4) at it.
            let percpu = Box::new(crate::kernel::percpu::PerCpuData::zeroed());
            let percpu_ptr = Box::into_raw(percpu);
            unsafe {
                (*percpu_ptr).cpu_id = 0; // BSP
                (*percpu_ptr).scheduler = &self.scheduler as *const Scheduler as *mut Scheduler;
            }
            crate::kernel::percpu::riscv64_set_tp(percpu_ptr as u64);

            // Store the PerCpuData pointer at the boot stack bottom so the
            // trap handler (trap.S) can load it into tp on every kernel entry.
            extern "C" {
                static __boot_stack_bottom: u8;
            }
            unsafe {
                let boot_stack_bottom = core::ptr::addr_of!(__boot_stack_bottom) as usize;
                *(boot_stack_bottom as *mut u64) = percpu_ptr as u64;
            }

            // Register the BSP scheduler in the per-CPU table so cross-CPU
            // operations (wake, reschedule IPI) can find it.
            crate::kernel::smp::register_percpu_scheduler(
                0,
                &self.scheduler as *const Scheduler as *mut Scheduler,
            );
            println!("[init  ] riscv64: BSP percpu cpu_id=0 tp set");
        }

        // ── Set NUMA node ID on the BSP per-CPU data ──
        if let Some(topo) = topology::global() {
            let node_id = topo.node_for_cpu(0);
            crate::kernel::percpu::get_mut().numa_node_id = node_id;
            println!("[init  ] BSP numa_node_id={}", node_id);
        }

        // ── SMP AP bring-up (x86_64) ──
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            if let Some(aps) = crate::kernel::smp::take_early_aps() {
                if !aps.is_empty() {
                    println!("[init  ] SMP: bringing up {} AP(s)...", aps.len());
                    crate::kernel::smp::bring_up_aps(&aps);
                }
            }
        }

        // ── SMP AP bring-up (AArch64) ──
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            crate::arch::aarch64::smp::bring_up_aps();
        }

        // ── SMP AP bring-up (RISC-V) ──
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            crate::arch::riscv64::smp::bring_up_aps();
        }

        // ── Power management (CPU frequency scaling) ──
        // Probe the architecture frequency driver and install the default
        // governor.  Safe on architectures without scaling support.
        crate::kernel::power::init();

        println!("[init  ] syscall table init...");
        self.syscall_table.init();
        // SAFETY: the syscall table is owned by the long-lived kernel object and
        // remains valid for all dispatches after initialization.
        unsafe {
            syscall::install_global_unchecked(&self.syscall_table);
        }
        let t6 = tick();
        boot.record_subsystem("syscall-table", SUBSYSTEM_STATUS_OK, t5, t6);

        // ── Init program ──────────────────────────────────────────────
        // Read the kernel command line to determine the init program path.
        // The distribution (protofire-os) passes `init=/system/init.elf` via
        // the bootloader (e.g. GRUB config).  Falls back to DEFAULT_INIT_PATH
        // when no command line is present.
        let cmdline = crate::arch::boot::multiboot2_command_line();
        let init_path = match cmdline {
            Some(ref cl) => {
                let path = crate::arch::boot::init_path_from_command_line(cl, DEFAULT_INIT_PATH);
                println!("[init  ] init path from cmdline: {}", path);
                // We need an owned copy since cmdline will be dropped.
                alloc::string::String::from(path)
            }
            None => {
                println!(
                    "[init  ] no cmdline; using default init path: {}",
                    DEFAULT_INIT_PATH
                );
                alloc::string::String::from(DEFAULT_INIT_PATH)
            }
        };
        self.spawn_init_program(&init_path);

        #[cfg(any(feature = "demo-disk", test))]
        {
            println!("[init  ] spawning demo threads...");
            self.spawn_system_programs();
        }
        println!("[init  ] starting idle process...");
        self.scheduler.start_idle_process();

        let t7 = tick();
        boot.record_subsystem("spawn", SUBSYSTEM_STATUS_OK, t6, t7);

        // ── BootReport: memory layout snapshot from heap bounds ──
        if let Some(mem) = memory::global() {
            let (heap_start, heap_end) = mem.heap_bounds();
            boot.set_memory_layout(
                (32 * 1024 * 1024) as u64, // physical total: 32 MiB
                (heap_end - heap_start) as u64,
                0, // page table root: not accessible from public API
                0, // kernel page count: not accessible from public API
                0, // user page count: not accessible from public API
            );
        }

        boot.finalise(t7);
        boot_report::BootReport::install_global(boot);

        self.initialized = true;
        println!("protofire kernel initialized");
    }

    /// Initialize the NUMA topology from ACPI SRAT/SLIT (x86_64) or FDT
    /// (AArch64/RISC-V), falling back to a single-node configuration when
    /// no NUMA tables are available.
    ///
    /// Must be called after the heap allocator is available (memory init) and
    /// before per-CPU data is queried for node affinity.
    fn init_numa(&self) {
        // ── x86_64: use ACPI SRAT/SLIT data discovered pre-page-table-switch
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if let Some(numa) = crate::kernel::smp::take_early_numa() {
            let topo = Self::build_numa_topology_from_srat(&numa);
            let node_count = topo.nodes.len();
            crate::kernel::topology::init(topo);
            if node_count > 1 {
                crate::println!("[init  ] NUMA: {} nodes from ACPI SRAT/SLIT", node_count);
            } else {
                crate::println!("[init  ] NUMA: single node from ACPI SRAT");
            }
            return;
        }

        // ── AArch64 / RISC-V: use FDT NUMA data
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        if let Some(topo) = crate::arch::fdt::build_fdt_numa_topology() {
            let node_count = topo.nodes.len();
            crate::kernel::topology::init(topo);
            if node_count > 1 {
                crate::println!("[init  ] NUMA: {} nodes from FDT", node_count);
            } else {
                crate::println!("[init  ] NUMA: single node from FDT");
            }
            return;
        }

        // ── Fallback: single-node configuration
        //
        // online_cpu_count() returns 1 before AP bring-up, so on x86_64
        // without ACPI SRAT we will only see the BSP.  On AArch64 and
        // RISC-V we can fall back to the FDT CPU count instead.
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        let cpu_count = crate::arch::fdt::cpu_count().max(1);
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        let cpu_count = crate::kernel::smp::online_cpu_count().max(1);
        let cpu_ids: alloc::vec::Vec<u32> = (0..cpu_count).collect();
        let cpu_to_node: alloc::vec::Vec<crate::kernel::topology::NodeId> =
            alloc::vec![0u8; cpu_count as usize];

        let topo = crate::kernel::topology::Topology {
            nodes: alloc::vec![crate::kernel::topology::NumaNode {
                id: 0,
                cpu_ids,
                memory_ranges: alloc::vec![(0, u64::MAX)],
            }],
            cpu_to_node,
            distance_matrix: alloc::vec::Vec::new(),
        };
        crate::kernel::topology::init(topo);
        crate::println!(
            "[init  ] NUMA: single-node topology (node 0, {} CPU(s))",
            cpu_count
        );
    }

    /// Build a [`Topology`] from ACPI SRAT/SLIT data.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn build_numa_topology_from_srat(
        numa: &crate::kernel::smp::EarlyNumaData,
    ) -> crate::kernel::topology::Topology {
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

        crate::kernel::topology::Topology {
            nodes,
            cpu_to_node,
            distance_matrix,
        }
    }

    /// Scan registered block devices for a swap area and initialise the
    /// swap subsystem if one is found.
    ///
    /// Uses the global memory manager so this method only needs an immutable
    /// `&self` reference, avoiding borrow conflicts with the `tick` closure.
    #[cfg(target_os = "none")]
    fn maybe_init_swap(&self) {
        use crate::kernel::memory::swap::probe_device;
        use alloc::sync::Arc;

        // Collect the current set of registered block devices.
        let devices = {
            let fs = self.fs.lock();
            fs.block_devices
                .iter()
                .map(|(name, dev)| (name.clone(), Arc::clone(dev)))
                .collect::<alloc::vec::Vec<_>>()
        };

        for (name, device) in &devices {
            if device.is_read_only() {
                continue;
            }
            match probe_device(device.as_ref()) {
                Some((start_lba, page_count)) => {
                    let result = crate::kernel::memory::global_mut()
                        .map(|mut mm| mm.init_swap(Arc::clone(device), start_lba, page_count));
                    match result {
                        Some(Ok(())) => {
                            crate::println!(
                                "[vm    ] swap: found area on '{}' ({} pages, ~{} MiB)",
                                name,
                                page_count,
                                (page_count * 4096) / (1024 * 1024)
                            );
                            return;
                        }
                        Some(Err(e)) => {
                            crate::println!(
                                "[vm    ] swap: failed to init on '{}': {}",
                                name,
                                e.as_str()
                            );
                        }
                        None => {
                            crate::println!("[vm    ] swap: global memory manager not available");
                        }
                    }
                }
                None => { /* no swap signature on this device — skip */ }
            }
        }

        crate::println!("[vm    ] swap: no swap device found, using in-memory content store");
    }

    pub fn run(&mut self) -> ! {
        println!("protofire kernel running");

        loop {
            // Drop any thread that terminated in the previous scheduling
            // epoch with interrupts enabled (see Scheduler::process_deferred_dying).
            self.scheduler.process_deferred_dying();
            arch::interrupts::disable();
            self.scheduler.schedule();

            arch::instructions::idle();
        }
    }

    /// Spawn kernel worker threads and user programs from service definitions.
    ///
    /// Tries to load services from `/system/rc.d/*.toml` on the boot
    /// filesystem. Falls back to an embedded configuration that matches the
    /// previous hard-coded behaviour when no config files are present.
    ///
    /// TODO(init): The embedded fallback config will move to protofire-os once
    /// the demo-disk builder also writes the rc.d config files.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_system_programs(&self) {
        // Try loading service definitions from the boot filesystem.
        let fs = self.fs.lock();
        let services = service::load_services_from_fs(&fs, service::SERVICE_CONFIG_DIR);
        drop(fs);

        if services.is_empty() {
            // Fall back to the embedded default configuration.
            self.spawn_embedded_default_services();
        } else {
            self.spawn_service_list(&services);
        }
    }

    /// Spawn services from a parsed list of service definitions.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_service_list(&self, services: &[service::ServiceDefinition]) {
        for svc in services {
            match svc.kind {
                service::ServiceKind::KernelThread => {
                    if let Some(entry_name) = &svc.entry {
                        if let Some(func) = resolve_worker(entry_name) {
                            self.scheduler.spawn_kernel_named(&svc.name, func);
                            println!("[service] kernel thread {} started", svc.name);
                        } else {
                            println!("[service] unknown worker entry: {}", entry_name);
                        }
                    }
                }
                service::ServiceKind::UserProgram => {
                    if let Some(path) = &svc.path {
                        println!("[service] spawning user program {} ({})", svc.name, path);
                        self.spawn_demo_user_program(path);
                    }
                }
            }
        }
    }

    /// Embedded default services that match the previous hard-coded behaviour.
    /// This is transitional — the distribution should provide
    /// `/system/rc.d/defaults.toml` instead.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_embedded_default_services(&self) {
        self.scheduler
            .spawn_kernel_named("kworker-a", demo_worker_a);
        self.scheduler
            .spawn_kernel_named("kworker-b", demo_worker_b);
        self.scheduler
            .spawn_kernel_named("kworker-syscall-fs", demo_syscall_fs_worker);

        println!(
            "[init  ] spawning shell ({})...",
            program::SHELL_CURRENT_PATH
        );
        self.spawn_demo_user_program(program::SHELL_CURRENT_PATH);
        println!("[init  ] shell spawn complete");

        #[cfg(target_arch = "x86_64")]
        {
            for launch_reference in [
                program::DEMO_RUST_IO_CURRENT_PATH,
                program::DEMO_CURRENT_PATH,
                program::DEMO_FAULT_CURRENT_PATH,
                program::DEMO_INVALID_OPCODE_CURRENT_PATH,
                program::DEMO_GENERAL_PROTECTION_CURRENT_PATH,
                program::DEMO_ONE_SHOT_PAGE_FAULT_CURRENT_PATH,
                program::DEMO_NESTED_PAGE_FAULT_CURRENT_PATH,
            ] {
                self.spawn_demo_user_program(launch_reference);
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            use crate::arch::mmu;
            if let Some(region) = mmu::demo_user_slot_layout(0) {
                println!(
                    "[user  ] prepared aarch64 EL0 demo slots={} entry={:#018x} stack={:#018x} exception-stack={:#018x} region={:#018x}..{:#018x}",
                    mmu::demo_user_slot_count(),
                    region.entry_point,
                    region.stack_top,
                    region.exception_stack_top,
                    region.region_start,
                    region.region_start + region.region_length
                );
            }
            for launch_reference in [program::DEMO_CURRENT_PATH, program::DEMO_RUST_CURRENT_PATH] {
                self.spawn_demo_user_program(launch_reference);
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            use crate::arch::mmu;
            if let Some(region) = mmu::demo_user_slot_layout(0) {
                println!(
                    "[user  ] prepared riscv64 U-mode demo slots={} entry={:#018x} stack={:#018x} exception-stack={:#018x} region={:#018x}..{:#018x}",
                    mmu::demo_user_slot_count(),
                    region.entry_point,
                    region.stack_top,
                    region.exception_stack_top,
                    region.region_start,
                    region.region_start + region.region_length
                );
            }
            for launch_reference in [program::DEMO_CURRENT_PATH, program::SHELL_CURRENT_PATH] {
                self.spawn_demo_user_program(launch_reference);
            }
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )))]
        {
            println!("[user  ] demo user programs are unavailable on this architecture");
        }
    }

    #[allow(dead_code)]
    #[cfg(not(target_os = "none"))]
    fn spawn_system_programs(&self) {}

    /// Spawn the init program from a filesystem path.
    ///
    /// Reads the ELF at `init_path`, prepares a user address space, and
    /// launches it as a user process.  If the path does not exist (no boot
    /// disk attached, or distribution not installed) the kernel prints a
    /// diagnostic and continues.
    #[cfg(target_os = "none")]
    fn spawn_init_program(&self, init_path: &str) {
        let fs = self.fs.lock();
        match program::load_from_filesystem(&fs, "/", init_path) {
            Ok(loaded) => {
                drop(fs);
                match program::launch_loaded_program_with_security_token(
                    &self.scheduler,
                    loaded,
                    SecurityToken::guest(),
                    false, // start_suspended
                ) {
                    Ok(launched) => {
                        println!("[init  ] init spawned pid={}", launched.process.pid());
                    }
                    Err(error) => {
                        println!("[init  ] init spawn failed: {}", error.as_str());
                    }
                }
            }
            Err(_error) => {
                println!(
                    "[init  ] No init program found at {} — is the boot disk attached?",
                    init_path
                );
            }
        }
    }

    #[cfg(not(target_os = "none"))]
    fn spawn_init_program(&self, _init_path: &str) {}

    #[cfg(any(test, target_os = "none"))]
    fn recover_install_management_state(&self) -> (u64, u64) {
        let recovery = {
            let fs = self.fs.lock();
            program::recover_install_management_state(&fs)
        };

        match recovery {
            Ok(recovery) => {
                let transactions_recovered = recovery.recovered_transactions.len() as u64;
                let transactions_repaired = recovery.repaired_transaction_logs.len() as u64;
                if let Some(error) = recovery.transaction_recovery_error {
                    println!(
                        "[apps  ] install transaction recovery incomplete error={}",
                        error.as_str()
                    );
                }
                if let Some(error) = recovery.download_cache_recovery_error {
                    println!(
                        "[apps  ] download cache recovery incomplete error={}",
                        error.as_str()
                    );
                }
                for recovered in recovery.recovered_transactions {
                    println!(
                        "[apps  ] recovered install {}@{} outcome={}",
                        recovered.app_id,
                        recovered.version,
                        install_recovery_outcome_label(recovered.outcome)
                    );
                }
                for repaired in recovery.repaired_transaction_logs {
                    println!(
                        "[apps  ] repaired transaction log path={} kind={} reason={}",
                        repaired.path,
                        transaction_log_entry_kind_label(repaired.entry_kind),
                        transaction_log_repair_reason_label(repaired.reason)
                    );
                }
                for repaired in recovery.repaired_download_cache {
                    println!(
                        "[apps  ] repaired download cache root={} app={} version={} stage={} outcome={} source={}",
                        repaired.root_path,
                        repaired.app_id.as_deref().unwrap_or("-"),
                        repaired.version.as_deref().unwrap_or("-"),
                        repaired.staging_state.as_deref().unwrap_or("-"),
                        download_cache_prune_outcome_label(repaired.outcome),
                        repaired.source_reference.as_deref().unwrap_or("-")
                    );
                }
                (transactions_recovered, transactions_repaired)
            }
            Err(error) => {
                println!(
                    "[apps  ] install management recovery skipped error={}",
                    error.as_str()
                );
                (0, 0)
            }
        }
    }

    #[cfg(not(any(test, target_os = "none")))]
    fn recover_install_management_state(&self) -> (u64, u64) {
        (0, 0)
    }

    /// Run `check_and_repair_volume` on every mounted volume (skipping the
    /// synthetic root "/") and return `(volumes_checked, repairs_applied)`.
    /// Also stores a detailed `VolumeRecoverySummary` globally for runtime
    /// query via the `SystemHealth` syscall.
    fn recover_volumes(&self) -> (u64, u64) {
        let fs = self.fs.lock();
        let mount_points = fs.mount_points();
        let mut volumes_checked: u64 = 0;
        let mut repairs_applied: u64 = 0;
        let mut summary = VolumeRecoverySummary::default();

        for mount in &mount_points {
            if mount.path == "/" {
                continue;
            }
            match fs.check_and_repair_volume(&mount.path) {
                Ok(report) => {
                    volumes_checked += 1;
                    summary.volumes_checked += 1;
                    summary.repairs_applied += report.repairs_applied as u64;
                    summary.issues_detected += report.issues_detected as u64;
                    summary.orphan_data_blocks += report.orphan_data_blocks as u64;
                    summary.checksum_failures += report.checksum_failures as u64;
                    summary.staging_orphans_cleaned += report.staging_orphans_cleaned as u64;
                    summary.orphan_blocks_cleaned += report.orphan_blocks_cleaned as u64;
                    summary.interrupted_commits += report.interrupted_commits as u64;
                    if report.repairs_applied > 0 {
                        repairs_applied += 1;
                        println!(
                            "[recovery] {}: {} issue(s) {} repair(s) {} orphan(s) {} checksum(s) {} staging(s) {} intr(s)",
                            mount.path,
                            report.issues_detected,
                            report.repairs_applied,
                            report.orphan_data_blocks,
                            report.checksum_failures,
                            report.staging_orphans_cleaned,
                            report.interrupted_commits
                        );
                    } else if report.issues_detected > 0 {
                        println!(
                            "[recovery] {}: {} issue(s) no repairs needed",
                            mount.path, report.issues_detected
                        );
                    } else {
                        println!("[recovery] {}: clean", mount.path);
                    }
                }
                Err(e) => {
                    println!(
                        "[recovery] {}: check failed error={}",
                        mount.path,
                        e.as_str()
                    );
                }
            }
        }

        install_volume_recovery_summary(summary);
        (volumes_checked, repairs_applied)
    }

    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_demo_user_program(&self, launch_reference: &str) -> Option<program::LaunchedProgram> {
        println!("[user  ] spawn_demo_user_program: {}", launch_reference);
        match program::spawn_from_global(&self.scheduler, launch_reference) {
            Ok(launched) => {
                let loaded = &launched.loaded;
                println!(
                    "[user  ] loaded {} id={} version={} argc={} envc={} entry=0x{:x} machine=0x{:x} segments={} ({} bytes)",
                    loaded.path,
                    loaded.catalog_id,
                    loaded.version,
                    loaded.arguments.len(),
                    loaded.environment.len(),
                    loaded.entry_point,
                    loaded.machine,
                    loaded.load_segment_count(),
                    loaded.image_len
                );

                if let Some(layout) = loaded.image_layout.as_ref() {
                    println!(
                        "[user  ] image-plan span={:#018x}..{:#018x} pages={} stack={:#018x}..{:#018x} guard={:#018x}..{:#018x}",
                        layout.image_start,
                        layout.image_end,
                        layout.mapped_page_count(),
                        layout.stack_bottom,
                        layout.stack_top,
                        layout.stack_guard_start,
                        layout.stack_guard_end
                    );
                }

                if let Some(summary) = loaded.process_address_space_summary() {
                    println!(
                        "[user  ] process-root root={:#018x} pages={} kernel={} user={} tables={}",
                        summary.root_table_address,
                        summary.mapped_page_count,
                        summary.kernel_page_count,
                        summary.user_page_count,
                        summary.table_page_count
                    );
                }

                Some(launched)
            }
            Err(error) => {
                println!(
                    "[user  ] load failed catalog={} error={}",
                    launch_reference,
                    error.as_str()
                );

                None
            }
        }
    }

    #[allow(dead_code)]
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn log_demo_storage_sample(&self) {
        let Some(fs) = fs::global() else {
            return;
        };

        let mut sample = [0_u8; DEMO_README_SAMPLE_BYTES];
        let preview = {
            let fs = fs.lock();
            let Ok(mut file) = fs.open(DEMO_README_SAMPLE_PATH, 0) else {
                println!("[demo  ] fs sample open failed");
                return;
            };

            let Ok(bytes) = file.read(&mut sample) else {
                println!("[demo  ] fs sample read failed");
                return;
            };

            core::str::from_utf8(&sample[..bytes]).unwrap_or("<binary>")
        };

        println!("[demo  ] fs sample {:?}", preview);
    }

    #[allow(dead_code)]
    #[cfg(not(target_os = "none"))]
    fn log_demo_storage_sample(&self) {}

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn prepare_arch_paging(&self) {
        let prepared =
            crate::arch::mmu::prepare_runtime_kernel_page_tables(self.memory.heap_bounds());

        match prepared {
            Some(summary) => {
                println!(
                    "[mem   ] prepared x86_64 kernel page tables root={:#018x} windows={} pages={}",
                    summary.root_table_address, summary.window_count, summary.mapped_page_count
                );

                match crate::arch::mmu::activate_prepared_runtime_kernel_page_tables() {
                    Some(active) => {
                        println!(
                            "[mem   ] activated x86_64 kernel page tables old={:#018x} new={:#018x} already_active={} windows={} pages={}",
                            active.previous_root_table_address,
                            active.active_root_table_address,
                            active.already_active,
                            active.window_count,
                            active.mapped_page_count
                        );

                        match crate::arch::mmu::active_runtime_kernel_page_table_check(
                            self.memory.heap_bounds(),
                        ) {
                            Some(check) => {
                                println!(
                                    "[mem   ] active paging check root={:#018x} rip={:#018x}/{}:{} rsp={:#018x}/{}:{} heap={:#018x}/{}:{}",
                                    check.root_table_address,
                                    check.instruction_pointer.virtual_address,
                                    check.instruction_pointer.kind.as_str(),
                                    check.instruction_pointer.permissions.as_rwx(),
                                    check.stack_pointer.virtual_address,
                                    check.stack_pointer.kind.as_str(),
                                    check.stack_pointer.permissions.as_rwx(),
                                    check.heap_pointer.virtual_address,
                                    check.heap_pointer.kind.as_str(),
                                    check.heap_pointer.permissions.as_rwx()
                                );
                            }
                            None => {
                                println!("[mem   ] active paging self-check failed");
                            }
                        }
                    }
                    None => {
                        println!("[mem   ] failed to activate x86_64 kernel page tables");
                    }
                }
            }
            None => {
                println!("[mem   ] failed to prepare x86_64 kernel page tables");
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    fn prepare_arch_paging(&self) {
        let prepared =
            crate::arch::mmu::prepare_runtime_kernel_page_tables(self.memory.heap_bounds());

        match prepared {
            Some(summary) => {
                println!(
                    "[mem   ] prepared aarch64 kernel page tables root={:#018x} windows={} pages={}",
                    summary.root_table_address, summary.window_count, summary.mapped_page_count
                );

                match crate::arch::mmu::activate_prepared_runtime_kernel_page_tables() {
                    Some(active) => {
                        println!(
                            "[mem   ] activated aarch64 kernel page tables old={:#018x} new={:#018x} already_active={} windows={} pages={}",
                            active.previous_root_table_address,
                            active.active_root_table_address,
                            active.already_active,
                            active.window_count,
                            active.mapped_page_count
                        );

                        if let Some(check) =
                            crate::arch::mmu::active_runtime_kernel_page_table_check(
                                self.memory.heap_bounds(),
                            )
                        {
                            println!(
                                "[mem   ] active paging check root={:#018x} rip={:#018x}/{}:{} rsp={:#018x}/{}:{} heap={:#018x}/{}:{}",
                                check.root_table_address,
                                check.instruction_pointer.virtual_address,
                                check.instruction_pointer.kind.as_str(),
                                check.instruction_pointer.permissions.as_rwx(),
                                check.stack_pointer.virtual_address,
                                check.stack_pointer.kind.as_str(),
                                check.stack_pointer.permissions.as_rwx(),
                                check.heap_pointer.virtual_address,
                                check.heap_pointer.kind.as_str(),
                                check.heap_pointer.permissions.as_rwx()
                            );
                        } else {
                            println!("[mem   ] active aarch64 paging self-check unavailable");
                        }
                    }
                    None => {
                        println!("[mem   ] failed to activate aarch64 kernel page tables");
                    }
                }
            }
            None => {
                println!("[mem   ] failed to prepare aarch64 kernel page tables");
            }
        }
    }

    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    fn prepare_arch_paging(&self) {
        let prepared =
            crate::arch::mmu::prepare_runtime_kernel_page_tables(self.memory.heap_bounds());

        match prepared {
            Some(summary) => {
                println!(
                    "[mem   ] prepared riscv64 kernel page tables root={:#018x} windows={} pages={}",
                    summary.root_table_address, summary.window_count, summary.mapped_page_count
                );

                match crate::arch::mmu::activate_prepared_runtime_kernel_page_tables() {
                    Some(active) => {
                        println!(
                            "[mem   ] activated riscv64 kernel page tables old={:#018x} new={:#018x} already_active={} windows={} pages={}",
                            active.previous_root_table_address,
                            active.active_root_table_address,
                            active.already_active,
                            active.window_count,
                            active.mapped_page_count
                        );

                        match crate::arch::mmu::active_runtime_kernel_page_table_check(
                            self.memory.heap_bounds(),
                        ) {
                            Some(check) => {
                                println!(
                                    "[mem   ] active paging check root={:#018x} rip={:#018x}/{}:{} rsp={:#018x}/{}:{} heap={:#018x}/{}:{}",
                                    check.root_table_address,
                                    check.instruction_pointer.virtual_address,
                                    check.instruction_pointer.kind.as_str(),
                                    check.instruction_pointer.permissions.as_rwx(),
                                    check.stack_pointer.virtual_address,
                                    check.stack_pointer.kind.as_str(),
                                    check.stack_pointer.permissions.as_rwx(),
                                    check.heap_pointer.virtual_address,
                                    check.heap_pointer.kind.as_str(),
                                    check.heap_pointer.permissions.as_rwx()
                                );
                            }
                            None => {
                                println!("[mem   ] active riscv64 paging self-check unavailable");
                            }
                        }
                    }
                    None => {
                        println!("[mem   ] failed to activate riscv64 kernel page tables");
                    }
                }
            }
            None => {
                println!("[mem   ] failed to prepare riscv64 kernel page tables");
            }
        }
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "none"),
        all(target_arch = "aarch64", target_os = "none"),
        all(target_arch = "riscv64", target_os = "none")
    )))]
    fn prepare_arch_paging(&self) {}
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_worker_a() {
    #[cfg(protofire_trusted_key)]
    {
        crate::println!("[e2e] demo_worker_a starting...");
    }
    run_demo_worker("worker-a");
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_worker_b() {
    run_demo_worker("worker-b");
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_syscall_fs_worker() {
    let mut table = syscall::Table::new();
    table.init();

    let path = DEMO_README_SAMPLE_PATH.as_bytes();
    let mut open_ctx = UserSyscall::open(
        path.as_ptr() as usize,
        path.len(),
        crate::abi::io::OPEN_FLAG_READ,
    );
    let fd = match table.dispatch(&mut open_ctx) {
        Ok(fd) => fd,
        Err(error) => {
            println!("[demo  ] syscall open failed: {}", error.as_str());
            return;
        }
    };

    let mut buffer = [0_u8; DEMO_README_SAMPLE_BYTES];
    let mut read_ctx = UserSyscall::read(fd, buffer.as_mut_ptr() as usize, buffer.len(), 0);
    let count = match table.dispatch(&mut read_ctx) {
        Ok(count) => count,
        Err(error) => {
            println!("[demo  ] syscall read failed: {}", error.as_str());
            return;
        }
    };

    let preview = core::str::from_utf8(&buffer[..count]).unwrap_or("<binary>");
    println!("[demo  ] syscall fs {:?}", preview);

    let mut close_ctx = UserSyscall::close(fd);
    if let Err(error) = table.dispatch(&mut close_ctx) {
        println!("[demo  ] syscall close failed: {}", error.as_str());
    }
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn run_demo_worker(name: &str) {
    for step in 0..DEMO_WORKER_STEPS {
        println!("[demo  ] {} step {}", name, step);
        process::sleep_current(DEMO_WORKER_SLEEP_TICKS);
    }

    println!("[demo  ] {} done", name);
}

#[cfg(any(test, target_os = "none"))]
fn install_recovery_outcome_label(
    outcome: program::InstallTransactionRecoveryOutcome,
) -> &'static str {
    match outcome {
        program::InstallTransactionRecoveryOutcome::CleanedPartialState => "cleaned_partial_state",
        program::InstallTransactionRecoveryOutcome::ReconciledInstalledState => {
            "reconciled_installed_state"
        }
        program::InstallTransactionRecoveryOutcome::ActivatedInstalledVersion => {
            "activated_installed_version"
        }
    }
}

#[cfg(any(test, target_os = "none"))]
fn download_cache_prune_outcome_label(outcome: program::DownloadCachePruneOutcome) -> &'static str {
    match outcome {
        program::DownloadCachePruneOutcome::RemovedInvalidEntry => "removed_invalid_entry",
        program::DownloadCachePruneOutcome::RemovedInstalledDuplicate => {
            "removed_installed_duplicate"
        }
    }
}

#[cfg(any(test, target_os = "none"))]
fn transaction_log_repair_reason_label(
    reason: program::TransactionLogRepairReason,
) -> &'static str {
    match reason {
        program::TransactionLogRepairReason::InvalidReference => "invalid_reference",
        program::TransactionLogRepairReason::UnexpectedEntryKind => "unexpected_entry_kind",
        program::TransactionLogRepairReason::UnexpectedEntryName => "unexpected_entry_name",
    }
}

#[cfg(any(test, target_os = "none"))]
fn transaction_log_entry_kind_label(kind: fs::NodeKind) -> &'static str {
    match kind {
        fs::NodeKind::Directory => "directory",
        fs::NodeKind::File => "file",
        fs::NodeKind::Device => "device",
        fs::NodeKind::Symlink => "symlink",
    }
}

// ── Worker registry ─────────────────────────────────────────────────────────
// Maps worker entry names (from service config files) to kernel thread
// entry-point functions.  Extended by the distribution when it needs
// additional kernel worker threads.

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
struct WorkerEntry {
    name: &'static str,
    func: fn(),
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
static WORKER_REGISTRY: &[WorkerEntry] = &[
    WorkerEntry {
        name: "demo_worker_a",
        func: demo_worker_a,
    },
    WorkerEntry {
        name: "demo_worker_b",
        func: demo_worker_b,
    },
    WorkerEntry {
        name: "demo_syscall_fs_worker",
        func: demo_syscall_fs_worker,
    },
];

/// Resolve a worker entry name to its function pointer.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn resolve_worker(name: &str) -> Option<fn()> {
    for entry in WORKER_REGISTRY {
        if entry.name == name {
            return Some(entry.func);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::fs::NodeKind;
    use crate::kernel::fs::{self};
    use crate::Error;

    fn ensure_dir(fs: &FileSystem, path: &str) {
        match fs.stat_path(path) {
            Ok(metadata) => assert_eq!(metadata.kind, NodeKind::Directory),
            Err(Error::NotFound) => fs.create_dir(path).expect("create test directory"),
            Err(error) => panic!("stat {} failed: {}", path, error.as_str()),
        }
    }

    fn write_text_file(fs: &FileSystem, path: &str, text: &str) {
        let mut file = fs
            .create_file(path, 0, 0, fs::OPEN_ALWAYS)
            .expect("create test file");
        file.set_len(0).expect("truncate test file");
        let written = fs
            .write(&mut file, text.as_bytes())
            .expect("write test file");
        assert_eq!(written, text.len());
    }

    #[test]
    fn recover_install_management_state_prunes_invalid_download_cache_entries() {
        let mut kernel = Kernel::new();
        kernel.init();

        {
            let fs = kernel.fs.lock();
            ensure_dir(&fs, "/data/downloads");
            ensure_dir(&fs, "/data/downloads/.staging");
            ensure_dir(&fs, "/data/downloads/orphaned-kernel-recovery");
            ensure_dir(&fs, "/data/downloads/.staging/kernel-demo-cache@1.0.0");
            write_text_file(
                &fs,
                "/data/downloads/orphaned-kernel-recovery/README.txt",
                "orphaned kernel recovery cache\n",
            );
            write_text_file(
                &fs,
                "/data/downloads/.staging/kernel-demo-cache@1.0.0/state.toml",
                "kind = \"download\"\napp_id = \"kernel-demo-cache\"\nversion = \"1.0.0\"\nsource_reference = \"/data/users/guest/downloads/kernel-demo-cache.toml\"\nstage = \"verified\"\n",
            );
        }

        kernel.recover_install_management_state();

        let fs = kernel.fs.lock();
        assert!(matches!(
            fs.stat_path("/data/downloads/orphaned-kernel-recovery"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            fs.stat_path("/data/downloads/.staging"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            fs.stat_path("/data/downloads"),
            Ok(metadata) if metadata.kind == NodeKind::Directory
        ));
    }

    #[test]
    fn recover_install_management_state_repairs_invalid_download_root_without_phase_failure() {
        let mut kernel = Kernel::new();
        kernel.init();

        {
            let fs = kernel.fs.lock();
            write_text_file(
                &fs,
                "/data/downloads",
                "download root replaced by file for recovery test\n",
            );
        }

        let recovery = {
            let fs = kernel.fs.lock();
            program::recover_install_management_state(&fs)
                .expect("recover install management state")
        };

        assert!(recovery.recovered_transactions.is_empty());
        assert_eq!(recovery.repaired_download_cache.len(), 1);
        assert_eq!(recovery.transaction_recovery_error, None);
        assert_eq!(recovery.download_cache_recovery_error, None);
        assert_eq!(
            recovery.repaired_download_cache[0].root_path,
            "/data/downloads"
        );
        assert_eq!(
            recovery.repaired_download_cache[0].outcome,
            program::DownloadCachePruneOutcome::RemovedInvalidEntry
        );
    }
}
