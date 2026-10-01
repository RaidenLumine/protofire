//! src/kernel/mod.rs
//!
//! Kernel bootstrap entry that wires memory, drivers, filesystem, scheduler,
//! and syscall table.

pub mod audit;
pub mod block;
pub mod boot_report;
pub mod compression;
pub mod config;
pub mod console;
pub mod crypto;
pub mod device;
pub mod handle_rights;
// Only the bare-metal polling threads emit heartbeats.
#[cfg(target_os = "none")]
pub mod heartbeat;
pub mod io;
pub mod ipc;
pub mod irq_balance;
pub mod irq_stats;
pub mod kernel_log;
pub mod maintenance;
pub mod nmi;
pub mod oom;
pub mod percpu;
pub mod power;
pub mod process;
pub mod procfs;
pub mod random;
pub mod scheduler;
pub mod security;
// Service-definition parsing (`/system/rc.d/*.toml`) is only exercised by the
// demo distribution's embedded default services; a pure kernel boot spawns
// the distribution's `/system/init.elf` directly and never reads rc.d.  The
// module is still built unconditionally because its runtime registry backs the
// `/service` filesystem, which every boot mounts.
pub mod service;
pub mod shm;
pub mod smp;
pub mod softirq;
pub mod sync;
pub mod topology;
pub mod user;
// A boot-time stress of the stack window and the TLB log; only the runtime
// check that asks for it builds it in.
#[cfg(target_os = "none")]
pub mod vm_churn;

// Only the demo-gated embedded-service helper builds a `ServiceDefinition`
// by hand; the config-driven path takes ownership of already-allocated
// strings from the parser.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use alloc::string::String;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use alloc::vec::Vec;

use crate::arch;
use crate::println;
#[cfg(any(test, target_os = "none"))]
use crate::user::program;
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
use crate::user::syscall::UserSyscall;

use crate::drivers::DriverManager;
use crate::fs::FileSystem;
use crate::memory::MemoryManager;
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
    syscall_table: crate::syscall::Table,
    initialized: bool,
}

impl Drop for Kernel {
    fn drop(&mut self) {
        crate::fs::uninstall_global(&self.fs);
        // Clear the thread-local scheduler pointer so that subsequent tests
        // on the same thread do not see a dangling pointer.  `crate::syscall::Table`
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
            syscall_table: crate::syscall::Table::new(),
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
            crate::memory::install_global_unchecked(&self.memory);
        }

        // ── SMP AP discovery (must run before prepare_arch_paging) ──
        // The bootstrap identity map is still active at this point, so
        // ACPI tables at arbitrary physical addresses are readable.
        // Also save the boot CR3 before we switch page tables — the AP
        // trampoline needs the bootstrap identity map (first 1 GiB).
        // ── Platform state the kernel needs before it switches tables ──
        // What has to be saved, and what the machine describes about itself,
        // are the machine's answers; the order they are asked in is here.
        crate::arch::platform::capture_early_state();
        crate::arch::platform::describe_platform();

        self.prepare_arch_paging();

        // The kernel's tables now describe what it says they do, or this says
        // where they do not — at boot, rather than from a fault later.
        crate::memory::arch::check_kernel_map_coverage();

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
        crate::arch::platform::enumerate_buses();

        // Initialize the bare-metal network stack if a VirtIO network device
        // was discovered during driver probing.  Start with a placeholder IP
        // (0.0.0.0), then run DHCP to obtain a real address.  Fall back to
        // QEMU's default guest IP (10.0.2.15) if DHCP fails.
        #[cfg(target_os = "none")]
        if let Some(net_device) = self.drivers.boot_net_device() {
            use crate::network::stack::NetworkStack;
            const DEFAULT_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
            NetworkStack::init_with_device(net_device, [0, 0, 0, 0]);
            println!("[kernel] network stack initialized");

            // Attempt DHCP address negotiation.
            let dhcp_result = crate::network::dhcp::discover_and_request();
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
                        lease.lease_ticks / crate::network::dhcp::TICKS_PER_SECOND,
                    );
                } else {
                    println!(
                        "[kernel] DHCP: assigned IP {}.{}.{}.{} (static fallback)",
                        assigned_ip[0], assigned_ip[1], assigned_ip[2], assigned_ip[3]
                    );
                }

                // ── IPv6 SLAAC ──
                // Armed here, driven by the tick path: the timer is configured
                // later in the boot than the network, so a routine that *waited*
                // on ticks would hang — which is why the blocking version was
                // skipped and left a TODO.  `start_slaac` only marks the
                // attempt; `advance_tick` sends the solicitations and watches
                // the address an advertisement forms.
                stack.start_slaac();
                crate::println!("[net   ] IPv6 SLAAC: armed (solicitation is tick-driven)");
            }
        }

        // SAFETY: the kernel object is created once during boot and never dropped
        // on the bare-metal execution path, so this reference remains valid.
        unsafe {
            crate::fs::install_global_unchecked(&self.fs);
        }
        // Devices the drivers find are published through the block layer and
        // land in the filesystem's device map, which is the only place that
        // owns one.  The hook is installed here because *this* is the layer
        // that knows both: a disk driver cannot name the filesystem, and the
        // filesystem cannot see the drivers.
        crate::kernel::block::set_device_publisher(|name, device| {
            if let Some(fs) = crate::fs::global() {
                fs.lock().register_block_device(name, device);
            }
        });
        // `/proc` is a view over the process table rather than a part of the
        // filesystem, so the mount is issued here, by the layer that knows
        // both.  It also has to wait for the global above: `mount_procfs`
        // looks it up, and when `fs`'s own layout tried this earlier there was
        // no global yet — the mount failed into a `let _ =` that no boot ever
        // reported, which is why `/proc` was not on the machine.
        if let Err(error) = crate::kernel::procfs::mount_procfs(crate::fs::PROCFS_MOUNT_PATH) {
            println!("[fs    ] procfs not mounted at /proc: {}", error.as_str());
        } else {
            println!("[fs    ] mounted procfs at /proc");
        }
        // Boot recovery walks and repairs every mounted volume while holding
        // the global filesystem lock.  Measured as its own scope because it is
        // a one-off whose cost is otherwise invisible in the syscall numbers.
        let (tx_recovered, tx_repaired, vol_checked, vol_repaired) =
            crate::fs::lock_timing::measure(
                crate::fs::lock_timing::LockScope::BootRecovery,
                || {
                    let (tx_recovered, tx_repaired) = self.recover_install_management_state();
                    let (vol_checked, vol_repaired) = self.recover_volumes();
                    (tx_recovered, tx_repaired, vol_checked, vol_repaired)
                },
            );
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
        // Devices whose interrupts are delivered by that controller: on
        // riscv64 the IMSIC programs the first MSI-X table it finds, which is
        // the half of a driver's contract that can be checked without a driver.
        crate::arch::platform::program_device_msix();
        println!("[init  ] timer init...");
        arch::timer::init();
        let t5 = tick();
        boot.record_subsystem("interrupts+timer", SUBSYSTEM_STATUS_OK, t4, t5);

        // ── NUMA topology initialisation ──
        self.init_numa();

        // ── Per-CPU data initialisation ──
        // The machine installs the BSP's block and says which logical CPU
        // this is; riscv64's answer is the hart the boot protocol named.
        let bsp_cpu_id =
            crate::arch::percpu::install_bsp(&self.scheduler as *const Scheduler as *mut Scheduler);
        debug_assert_eq!(bsp_cpu_id, crate::kernel::percpu::get_mut().cpu_id);

        // ── Set NUMA node ID on the BSP per-CPU data ──
        if let Some(topo) = topology::global() {
            // The CPU asking is the BSP, and which logical id that is belongs to
            // the architecture: 0 where the reset lands on CPU 0, and the hart
            // the boot protocol named on riscv64.
            let percpu = crate::kernel::percpu::get_mut();
            let node_id = topo.node_for_cpu(percpu.cpu_id);
            percpu.numa_node_id = node_id;
            println!("[init  ] BSP numa_node_id={}", node_id);
        }

        // ── SMP AP bring-up ──
        crate::arch::platform::bring_up_secondary_cpus();

        // ── Power management (CPU frequency scaling) ──
        // Probe the architecture frequency driver and install the default
        // governor.  Safe on architectures without scaling support.
        crate::kernel::power::init();

        println!("[init  ] syscall table init...");
        self.syscall_table.init();
        // SAFETY: the syscall table is owned by the long-lived kernel object and
        // remains valid for all dispatches after initialization.
        unsafe {
            crate::syscall::install_global_unchecked(&self.syscall_table);
        }
        let t6 = tick();
        boot.record_subsystem("syscall-table", SUBSYSTEM_STATUS_OK, t5, t6);

        // ── Audit subsystem ───────────────────────────────────────────
        // The ring buffer has to exist before anything can produce a record:
        // `emit_record` drops what it is handed until then, and the boot path
        // is itself a producer — a privileged service declaration is audited
        // below, in `service_security_token`.
        println!("[init  ] audit subsystem init...");
        crate::kernel::audit::init();
        println!(
            "[audit ] ring buffer installed ({} records)",
            crate::kernel::audit::global().map_or(0, |buffer| buffer.capacity())
        );

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
        // Deferred maintenance gets its own thread on every boot, not just the
        // demo one: the timer tick no longer performs the periodic write-back
        // itself, so something has to.
        #[cfg(target_os = "none")]
        self.scheduler.spawn_kernel_named(
            maintenance::MAINTENANCE_THREAD_NAME,
            maintenance::maintenance_entry,
        );

        // Ask the window and the invalidation log for more than they have,
        // before the idle process starts and the machine settles into its
        // steady state.  Compiled in by the churn feature only.
        #[cfg(target_os = "none")]
        vm_churn::run();

        println!("[init  ] starting idle process...");
        self.scheduler.start_idle_process();

        let t7 = tick();
        boot.record_subsystem("spawn", SUBSYSTEM_STATUS_OK, t6, t7);

        // ── BootReport: memory layout snapshot from heap bounds ──
        if let Some(mem) = crate::memory::global() {
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

    /// Initialize the NUMA topology from the table this machine keeps its
    /// NUMA description in, falling back to a single-node configuration when
    /// it has none.
    ///
    /// Must be called after the heap allocator is available (memory init) and
    /// before per-CPU data is queried for node affinity.
    fn init_numa(&self) {
        if let Some(topo) = crate::arch::platform::numa_topology() {
            crate::kernel::topology::init(topo);
            return;
        }

        // ── Fallback: single-node configuration
        //
        // online_cpu_count() returns 1 before AP bring-up, so on x86_64
        // without ACPI SRAT we will only see the BSP; the device-tree machines
        // count their `/cpus` nodes instead.
        let cpu_count = crate::arch::platform::reported_cpu_count();
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

    /// Scan registered block devices for a swap area and initialise the
    /// swap subsystem if one is found.
    ///
    /// Uses the global memory manager so this method only needs an immutable
    /// `&self` reference, avoiding borrow conflicts with the `tick` closure.
    #[cfg(target_os = "none")]
    fn maybe_init_swap(&self) {
        use crate::memory::swap::probe_device;
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
                    let result = crate::memory::global_mut()
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
        // Start the supervisor before any service, so a service that dies
        // during boot is already someone's problem.
        self.scheduler
            .spawn_kernel_named(SERVICE_SUPERVISOR_NAME, service_supervisor_entry);

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
    ///
    /// Every service is registered before any of them runs, so a service that
    /// fails to start still appears in `/service` next to the ones that did.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_service_list(&self, services: &[service::ServiceDefinition]) {
        let now_tick = self.scheduler.current_tick();
        for svc in services {
            service::register(svc, now_tick);
        }
        for svc in services {
            self.spawn_service(svc, now_tick, false);
        }
    }

    /// Spawn one service and record the outcome in the registry.
    ///
    /// Delegates to [`spawn_service`], which the supervisor thread also uses,
    /// so a boot-time spawn and a restart cannot drift apart in how they treat
    /// the registry.  The difference is only in how a user program is started:
    /// the boot path goes through [`Kernel::spawn_demo_user_program`], which
    /// logs the loaded image, and the supervisor spawns quietly because the
    /// image has already been described once.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_service(
        &self,
        svc: &service::ServiceDefinition,
        now_tick: u64,
        restart: bool,
    ) -> Option<u32> {
        spawn_service(
            &self.scheduler,
            svc,
            now_tick,
            restart,
            |path, security_token| {
                self.spawn_demo_user_program(path, security_token)
                    .map(|launched| launched.process.pid())
            },
        )
    }

    /// Register and spawn one embedded default service.
    ///
    /// The embedded defaults have no `/system/rc.d` declaration behind them, so
    /// this synthesises one.  That keeps the record `/service` reports for them
    /// the same shape as a config-driven service's, instead of the registry
    /// having two kinds of entry.
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_embedded_service(
        &self,
        name: &str,
        kind: service::ServiceKind,
        target: &str,
        auto_restart: bool,
        now_tick: u64,
    ) {
        let is_user_program = matches!(kind, service::ServiceKind::UserProgram);
        let definition = service::ServiceDefinition {
            name: String::from(name),
            kind,
            path: is_user_program.then(|| String::from(target)),
            entry: (!is_user_program).then(|| String::from(target)),
            args: Vec::new(),
            auto_restart,
            security: service::ServiceSecurity::Guest,
            account: None,
        };

        service::register(&definition, now_tick);
        self.spawn_service(&definition, now_tick, false);
    }

    /// Embedded default services that match the previous hard-coded behaviour.
    ///
    /// This is transitional — the distribution should provide
    /// `/system/rc.d/defaults.toml` instead.  Every service here is registered
    /// with `auto_restart = false`, for two reasons: the demo programs are
    /// one-shot by design — the fault demos exist to crash — and the shell must
    /// stay down once the user exits it, or `exit` would mean "come back in two
    /// seconds".  Restarting is additionally broken today; see
    /// [`service_supervisor_entry`].
    #[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
    fn spawn_embedded_default_services(&self) {
        let now_tick = self.scheduler.current_tick();

        for (name, entry) in [
            ("kworker-a", "demo_worker_a"),
            ("kworker-b", "demo_worker_b"),
            ("kworker-syscall-fs", "demo_syscall_fs_worker"),
        ] {
            self.spawn_embedded_service(
                name,
                service::ServiceKind::KernelThread,
                entry,
                false,
                now_tick,
            );
        }

        println!(
            "[init  ] spawning shell ({})...",
            program::SHELL_CURRENT_PATH
        );
        self.spawn_embedded_service(
            "shell",
            service::ServiceKind::UserProgram,
            program::SHELL_CURRENT_PATH,
            false,
            now_tick,
        );
        println!("[init  ] shell spawn complete");

        crate::arch::platform::describe_user_slots();
        for (launch_reference, auto_restart) in crate::arch::platform::demo_user_programs() {
            self.spawn_embedded_service(
                &service_name_for_program(launch_reference),
                service::ServiceKind::UserProgram,
                launch_reference,
                *auto_restart,
                now_tick,
            );
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
        // Hold the filesystem lock only for reading the image.  The second
        // phase calls `crate::memory::global_mut()`, and holding this lock across that
        // is the cross-CPU hazard the note on
        // `SpinLock::lock_without_irq_disable` describes: a TLB shootdown runs
        // under the memory-manager lock, and this lock masks interrupts, so
        // this CPU could not acknowledge one while waiting for that lock.
        let image = {
            let fs = self.fs.lock();
            program::load_filesystem_image(&fs, "/", init_path)
        };

        match image
            .and_then(|(descriptor, image)| program::finish_loading_program(descriptor, image))
        {
            Ok(loaded) => {
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
    fn spawn_demo_user_program(
        &self,
        launch_reference: &str,
        security_token: SecurityToken,
    ) -> Option<program::LaunchedProgram> {
        println!("[user  ] spawn_demo_user_program: {}", launch_reference);
        match program::spawn_from_global_with_security_token(
            &self.scheduler,
            launch_reference,
            security_token,
        ) {
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
        let Some(fs) = crate::fs::global() else {
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

    /// Prepare and switch to this machine's runtime kernel page tables.
    fn prepare_arch_paging(&self) {
        crate::arch::mmu::install_runtime_kernel_page_tables(self.memory.heap_bounds());
    }
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_worker_a() {
    run_demo_worker("worker-a");
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_worker_b() {
    run_demo_worker("worker-b");
}

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn demo_syscall_fs_worker() {
    let mut table = crate::syscall::Table::new();
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
fn transaction_log_entry_kind_label(kind: crate::fs::NodeKind) -> &'static str {
    match kind {
        crate::fs::NodeKind::Directory => "directory",
        crate::fs::NodeKind::File => "file",
        crate::fs::NodeKind::Device => "device",
        crate::fs::NodeKind::Symlink => "symlink",
    }
}

// ── Worker registry ─────────────────────────────────────────────────────────
// Maps worker entry names (from service config files) to kernel thread
// entry-point functions.  Extended by the distribution when it needs
// additional kernel worker threads.

/// Derive a service name from a program path.
///
/// `/system/demo-fault.elf` becomes `demo-fault` and
/// `/apps/current/shell.toml` becomes `shell`.  A service name is one path
/// component in `/service`, so it cannot contain a slash, and neither the
/// directory nor the extension carries information the registry does not
/// already hold — the full path is still in `/service/<name>/describe`.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn service_name_for_program(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let stem = match file.rsplit_once('.') {
        // A leading dot names a hidden file rather than an extension, so
        // `.profile` keeps its name.
        Some((stem, _extension)) if !stem.is_empty() => stem,
        _ => file,
    };
    String::from(stem)
}

/// How often the supervisor thread wakes up, in scheduler ticks.
///
/// This bounds the delay between a service dying and the system noticing.  A
/// quarter of a second is well inside human perception for a service that is
/// down, and the supervisor sleeps between passes, so the interval costs
/// nothing when nothing has failed.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const SERVICE_SUPERVISOR_POLL_TICKS: u64 = 25;

/// Name of the kernel thread that supervises services.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
const SERVICE_SUPERVISOR_NAME: &str = "service-supervisor";

/// Spawn one service and record the outcome in the registry.
///
/// Returns the new instance's PID, or `None` when the service could not be
/// started — in which case the registry already holds the reason, so
/// `/service/<name>/describe` can still answer for a boot log that has
/// scrolled away.
///
/// `restart` says whether this spawn is a supervisor retry.  It only changes
/// the bookkeeping: the attempt is charged against the restart budget before
/// the spawn is attempted, so a service whose program can never be loaded is
/// retired instead of retried forever.
///
/// `launch_user_program` is how a user-program service is started.  It is a
/// parameter rather than a call so that this function stays independent of
/// `Kernel`, which is what lets the supervisor thread — a plain `fn()` with no
/// access to the kernel object — share the implementation.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn spawn_service(
    scheduler: &Scheduler,
    svc: &service::ServiceDefinition,
    now_tick: u64,
    restart: bool,
    launch_user_program: impl FnOnce(&str, SecurityToken) -> Option<u32>,
) -> Option<u32> {
    if restart {
        service::note_restart_attempt(&svc.name, now_tick);
    }

    let pid = match svc.kind {
        service::ServiceKind::KernelThread => {
            let entry_name = svc.entry.as_deref().unwrap_or("");
            match resolve_worker(entry_name) {
                Some(func) => {
                    println!("[service] kernel thread {} started", svc.name);
                    Some(scheduler.spawn_kernel_named(&svc.name, func).pid())
                }
                None => {
                    println!("[service] unknown worker entry: {}", entry_name);
                    service::mark_failed(&svc.name, "unknown worker entry", now_tick);
                    None
                }
            }
        }
        service::ServiceKind::UserProgram => match svc.path.as_deref() {
            Some(path) => match service_security_token(svc) {
                Some(security_token) => {
                    println!("[service] spawning user program {} ({})", svc.name, path);
                    match launch_user_program(path, security_token) {
                        Some(pid) => Some(pid),
                        None => {
                            service::mark_failed(
                                &svc.name,
                                "user program failed to load",
                                now_tick,
                            );
                            None
                        }
                    }
                }
                None => {
                    service::mark_failed(
                        &svc.name,
                        "privileged declaration without a resolvable account",
                        now_tick,
                    );
                    None
                }
            },
            None => {
                println!("[service] {} declares no program path", svc.name);
                service::mark_failed(&svc.name, "no program path declared", now_tick);
                None
            }
        },
    };

    if let Some(pid) = pid {
        service::mark_running(&svc.name, Some(pid), now_tick);
    }
    pid
}

/// The token a user program service runs under, resolved through the account
/// database.
///
/// A service that declares nothing above `guest` has no identity to prove and
/// gets the guest token.  A privileged declaration names an account — `root`
/// when it does not say — and that name has to resolve before the service may
/// run: privilege is refused, never downgraded, because a service that asked
/// for `admin` and quietly got `guest` looks exactly like one that was
/// authorised, from the outside.
///
/// Both outcomes are audited.  This is the one place the kernel hands out
/// privilege without a password, so it is also the one place that has to
/// leave a trace where the audit log can see it.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
static SERVICE_AUDIT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn service_security_token(svc: &service::ServiceDefinition) -> Option<SecurityToken> {
    let Some(account_name) = svc.account_name() else {
        return Some(SecurityToken::guest());
    };

    let account = user::find_account(account_name);
    audit_service_privilege(svc, account_name, account.is_some());

    let Some(record) = account else {
        println!(
            "[service] {} declares `security = \"{}\"` but account `{}` is not in the user database",
            svc.name,
            svc.security.as_str(),
            account_name
        );
        return None;
    };

    // The only error this can produce is the missing account, which was
    // rejected above; a resolution that got this far produces a token.
    svc.security
        .security_token(Some((record.uid, record.gid)))
        .ok()
}

/// Record a privileged service declaration and whether it was honoured.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn audit_service_privilege(svc: &service::ServiceDefinition, account: &str, granted: bool) {
    use crate::kernel::audit::types::AuditEventType;
    use crate::kernel::audit::types::AuditRecord;

    // "<name> <level> <account>": the three facts a reader needs, and a shape
    // that stays legible in the hex the persistence layer writes.
    let mut payload = [0_u8; 96];
    let mut written = 0;
    for field in [svc.name.as_str(), svc.security.as_str(), account] {
        if written > 0 {
            payload[written] = b' ';
            written += 1;
        }
        let bytes = field.as_bytes();
        let take = bytes.len().min(payload.len() - written);
        payload[written..written + take].copy_from_slice(&bytes[..take]);
        written += take;
    }

    let (pid, timestamp) = crate::kernel::audit::current_actor();
    let uid = svc
        .account_name()
        .and_then(user::find_account)
        .map_or(0, |record| record.uid);
    let mut audit_record = AuditRecord::zeroed();
    audit_record.fill(
        SERVICE_AUDIT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        0,
        timestamp,
        AuditEventType::AuthEvent,
        pid,
        uid,
        if granted { 0 } else { -1 },
        &payload[..written],
    );
    let _ = crate::kernel::audit::emit_record(audit_record);
}

/// The service supervisor.
///
/// This runs as a sleeping kernel thread rather than from the idle loop.  The
/// idle thread is only chosen when nothing else is runnable, so a single
/// userspace process that never blocks — a shell polling the console, a
/// spinning worker — can keep supervision from running at all.  Sleeping on
/// the scheduler's own wait queue makes the supervisor an ordinary thread that
/// is guaranteed a turn, and costs nothing between passes.
///
/// # Runtime respawn
///
/// This is the kernel's first caller that spawns a process from an
/// already-scheduled thread, rather than from the boot thread before
/// `Kernel::run`.  That turned out to expose a latent uniprocessor wedge, and
/// the reason is worth keeping written down because `auto_restart` now
/// exercises it on every boot.
///
/// The symptom was a machine that went completely silent: no output, no timer,
/// no progress, at the `processes.lock()` inside
/// `Scheduler::register_spawned_thread`.  The cause was a lock-discipline
/// mismatch.  `kernel::sync::Mutex` is a `SpinLock`, which masks interrupts for
/// its whole critical section, but the memory manager's own lock did not.  So:
///
/// 1. A thread took the memory-manager lock and was preempted by the timer,
///    which was permitted because interrupts were never masked.
/// 2. The supervisor took `processes.lock()` — masking interrupts — and inside
///    it grew a `Vec`, reached the heap allocator, and called into the memory
///    manager.
/// 3. The supervisor then spun on the memory-manager lock with interrupts
///    masked.  The holder could only be rescheduled by the timer, and the timer
///    needed interrupts.  Neither side could move again.
///
/// With one thread and no preemption this was unreachable, which is why every
/// boot-time spawn had always worked.  The fix is the one this file's history
/// points at: keep both lock families on the same discipline, so a holder is
/// never preemptible.  See `MEMORY_MANAGER_LOCK` in
/// `src/memory/global.rs`.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
fn service_supervisor_entry() {
    let mut passes: u64 = 0;
    loop {
        process::sleep_current(SERVICE_SUPERVISOR_POLL_TICKS);
        passes += 1;

        let Some(scheduler) = Scheduler::global() else {
            continue;
        };
        let now_tick = scheduler.current_tick();

        // The second of two independent heartbeats; see
        // `kernel::heartbeat` for what the pair distinguishes.
        heartbeat::beat("supervisor", passes, now_tick);

        // Compute the whole plan before acting on any of it: restarting
        // re-enters the scheduler and the filesystem, and doing that while
        // holding the registry lock would deadlock against the next
        // `/service` read.
        let steps = service::plan_supervision(now_tick, |pid| {
            scheduler
                .process_by_pid(pid)
                .is_some_and(|process| process.state() != process::ProcessState::Terminated)
        });

        for step in steps {
            match step.action {
                service::SupervisionAction::Restart => {
                    let Some(record) = service::record(&step.name) else {
                        continue;
                    };
                    println!(
                        "[service] restarting {} (attempt {})",
                        step.name,
                        record.restarts.saturating_add(1)
                    );
                    spawn_service(
                        scheduler,
                        &record.definition,
                        now_tick,
                        true,
                        |path, security_token| {
                            program::spawn_from_global_with_security_token(
                                scheduler,
                                path,
                                security_token,
                            )
                            .ok()
                            .map(|launched| launched.process.pid())
                        },
                    );
                }
                service::SupervisionAction::Abandon => {
                    println!(
                        "[service] abandoning {} after its restart budget",
                        step.name
                    );
                    service::mark_abandoned(&step.name, "restart budget exhausted", now_tick);
                }
                service::SupervisionAction::LeaveStopped => {
                    println!("[service] {} stopped", step.name);
                    service::mark_stopped(&step.name, "process exited", now_tick);
                }
                service::SupervisionAction::WaitForBackoff => {}
            }
        }
    }
}

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
    use crate::fs::NodeKind;
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
            .create_file(path, 0, 0, crate::fs::OPEN_ALWAYS)
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
