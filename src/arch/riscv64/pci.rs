//! src/arch/riscv64/pci.rs
//!
//! RISC-V 64 PCIe: the shared walk, and wiring MSI-X to the IMSIC.
//!
//! Configuration space itself is the shared walk in [`crate::arch::pci`] —
//! the register offsets, the BAR probes, the capability chain, the bus scan —
//! and it is the same code the other architectures run.  What is left for
//! this platform to add is the enumeration: [`discover_ecam`] reads the
//! window the device tree describes — the same `pci-host-ecam-generic` node
//! aarch64 reads, which QEMU `virt` places at `0x3000_0000`, inside the
//! identity-mapped device window — [`probe_and_enumerate`] walks it and gives
//! the devices the BAR addresses that no firmware ran a pass for.
//!
//! What *is* here is the interrupt half: [`pci_enable_msix`] finds a device's
//! MSI-X capability and programs its table through the RISC-V AIA IMSIC, and
//! [`MsixClaim`] is the ownership that goes with it: a driver claims the
//! identities its device's table will deliver at probe time, and
//! [`program_device_msix`] programs the table with exactly those identities
//! once the controller is up.  A device nobody drives is claimed by the same
//! step, so the receive side is exercised rather than left as code nobody
//! runs — capability found, table's BAR and offset decoded, entries written
//! through the IMSIC and read back.
//!
//! ## References
//!
//! - PCI Firmware Specification, Revision 3.0, § 4.1 (ECAM)
//! - `linux/Documentation/devicetree/bindings/pci/host-generic-pci.txt`

use alloc::vec::Vec;

use crate::arch::fdt;
use crate::arch::pci::EcamRegion;
use crate::kernel::sync::Mutex;

/// The window the device tree describes, if it describes one.
///
/// Unlike the AArch64 copy of this, there is nothing to alias: QEMU `virt`
/// puts this machine's window at `0x3000_0000`, inside the identity-mapped
/// device window the kernel boots with, so the walk reads it where the device
/// tree says it is.  A machine that describes none has none — no constant
/// stands in for a window nobody named.
pub fn discover_ecam() -> Option<EcamRegion> {
    let info = fdt::platform_info();
    info.ecam_base.map(|base| {
        EcamRegion::new(
            base,
            info.ecam_start_bus.unwrap_or(0),
            info.ecam_end_bus.unwrap_or(255),
        )
    })
}

/// A discovered window and the devices found on it.
pub struct EcamProbe {
    /// The window, read at the address the device tree named.
    pub region: EcamRegion,
    /// Devices discovered on the enumerated buses.
    pub devices: Vec<PciDeviceInfo>,
}

/// Enumerate the devices a window covers.
///
/// The device tree says this machine's window covers buses 0 through 255 and
/// its devices are all on bus 0, so bus 0 is walked first and the rest only if
/// it answered nothing: a full walk is 65 536 config-space probes of space
/// that QEMU's machine leaves empty, at every boot.  A machine that hung its
/// devices off a bridge is still enumerated, at that price.
fn enumerate(region: &EcamRegion) -> Vec<PciDeviceInfo> {
    let first_bus = *region.buses().start();
    let devices = pci_enumerate_buses(region, first_bus..=first_bus);
    if !devices.is_empty() {
        return devices;
    }
    pci_enumerate_buses(region, region.buses())
}

/// Discover the window and enumerate what is attached to it.
pub fn probe_and_enumerate() -> Option<EcamProbe> {
    let region = discover_ecam()?;
    crate::println!(
        "[pci   ] RISC-V PCIe ECAM at {:#018x}, buses {}..={}",
        region.base_address(),
        region.buses().start(),
        region.buses().end()
    );
    let mut devices = enumerate(&region);
    // Nothing on this machine assigns BAR addresses, and a device whose BARs
    // are zero is not reachable — so the window the host bridge's `ranges`
    // describes becomes the addresses, before anything reads them back.
    assign_bars(&region, &mut devices);
    log_pci_devices(&region, &devices);
    Some(EcamProbe { region, devices })
}

/// Give the enumerated devices addresses out of the host bridge's memory
/// window, and say what happened.
///
/// A machine that describes no window gets no assignment: there is nowhere to
/// put a device, and inventing an address would be worse than leaving the BARs
/// at zero where a reader can see that nothing assigned them.
fn assign_bars(region: &EcamRegion, devices: &mut [PciDeviceInfo]) {
    let info = fdt::platform_info();
    let (Some(base), Some(size)) = (info.pcie_mmio_base, info.pcie_mmio_size) else {
        crate::println!("[pci   ] RISC-V: no PCIe memory window in the device tree");
        return;
    };
    let assignment =
        crate::arch::pci::assign_memory_bars(region, devices, base as u64, size as u64);
    crate::println!(
        "[pci   ] RISC-V BARs: {} assigned, window {:#018x}..{:#018x} of {:#018x}",
        assignment.assigned,
        base,
        assignment.used_end,
        (base as u64) + (size as u64)
    );
}

// The walk, re-exported so a caller naming this platform finds the whole
// vocabulary in one place.
pub use crate::arch::pci::cap_id;
pub use crate::arch::pci::find_device;
pub use crate::arch::pci::log_pci_devices;
pub use crate::arch::pci::pci_capability_find;
pub use crate::arch::pci::pci_capability_msi;
pub use crate::arch::pci::pci_capability_msix;
pub use crate::arch::pci::pci_capability_pcie;
pub use crate::arch::pci::pci_device_exists;
pub use crate::arch::pci::pci_enable_memory_and_bus_master;
pub use crate::arch::pci::pci_enumerate_buses;
pub use crate::arch::pci::pci_program_bar_64;
pub use crate::arch::pci::pci_read_bar_64;
pub use crate::arch::pci::pcie_check_hotplug_event;
pub use crate::arch::pci::pcie_read_slot_status;
pub use crate::arch::pci::probe_bar_size;
pub use crate::arch::pci::ConfigSpace;
pub use crate::arch::pci::MsiCapability;
pub use crate::arch::pci::MsixCapability;
pub use crate::arch::pci::PciBarInfo;
pub use crate::arch::pci::PciDeviceInfo;
pub use crate::arch::pci::PcieCapability;
pub use crate::arch::pci::PcieSlotCapabilities;

/// What programming a device's MSI-X table did.
#[derive(Clone, Copy)]
pub struct MsixProgramming {
    /// The first interrupt identity the table's entries deliver.
    pub first_irq: u32,
    /// Where the table is, inside the identity-mapped device window.
    pub table_phys: u64,
    /// How many entries were programmed.
    pub table_size: u32,
}

/// Program MSI-X for a PCIe device, delivering into the RISC-V AIA IMSIC.
///
/// Finds the device's MSI-X capability, derives the table address from the
/// capability's BAR indicator and offset, programs `count` entries through
/// [`crate::arch::riscv64::aia_imsic::configure_msix`] so they deliver
/// `base_irq..base_irq + count` to the IMSIC files `targets` names, and
/// enables the capability.
///
/// Returns where the entries went and which identity they deliver; the caller
/// registers a handler with
/// [`crate::arch::riscv64::aia_imsic::claim_device_irqs_each`] before the
/// device raises interrupts.
pub fn pci_enable_msix(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    base_irq: u32,
    targets: &[u32],
) -> Result<MsixProgramming, crate::Error> {
    use crate::arch::riscv64::aia_imsic;

    if !aia_imsic::has_aia_imsic() {
        return Err(crate::Error::NotImplemented);
    }

    let cap_off = pci_capability_find(region, bus, device, function, cap_id::MSI_X)
        .ok_or(crate::Error::NotImplemented)?;

    // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
    // found on this function.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };

    // Table BIR is bits 2:0 of the Table register; the offset is bits 31:3.
    let table_bir = (msix.table_bir_and_offset & 0x07) as u16;
    if table_bir >= 6 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_offset = (msix.table_bir_and_offset & 0xFFFF_FFF8) as u64;

    // The table writes, and the messages that follow, go nowhere until the
    // device decodes MMIO and may act as a bus master.
    pci_enable_memory_and_bus_master(region, bus, device, function);

    // A BAR of zero is a BAR nobody has assigned an address to; programming
    // entries through it would write over whatever physical address that is.
    let bar_base = pci_read_bar_64(
        region,
        bus,
        device,
        function,
        crate::arch::pci::reg::BAR0 + table_bir * 4,
    );
    if bar_base == 0 {
        return Err(crate::Error::InvalidArgument);
    }
    let table_phys = bar_base
        .checked_add(table_offset)
        .ok_or(crate::Error::InvalidArgument)?;

    // Table size is (Message Control bits 10:0) + 1 entries.
    let table_size = ((msix.message_control & 0x07FF) as u32) + 1;

    let first_irq = aia_imsic::configure_msix(table_phys, table_size, base_irq, targets)?;

    // Enable MSI-X (bit 15) and leave the *function mask* (bit 14) set: the
    // table is programmed, but the device may not signal yet.  Whichever side
    // owns the identities unmasks it — see [`msix_unmask`] — so a device's
    // first interrupt can never arrive before something is registered to
    // receive it, which is the difference between an interrupt the kernel can
    // attribute and one it counts as spurious.
    let new_control = msix.message_control | (1u16 << 15) | (1u16 << 14);
    // SAFETY: the message-control half of the MSI-X capability the walk found,
    // inside this function's configuration space.
    unsafe {
        region.write_u16(bus, device, function, cap_off as u16 + 2, new_control);
    }

    crate::println!(
        "[pci   ] RISC-V MSI-X enabled on {:02x}:{:02x}.{} ({} entr{}, irq {})",
        bus,
        device,
        function,
        table_size,
        if table_size == 1 { "y" } else { "ies" },
        first_irq
    );

    Ok(MsixProgramming {
        first_irq,
        table_phys,
        table_size,
    })
}

/// Let a device raise the interrupts its MSI-X table was programmed for.
///
/// The other half of [`pci_enable_msix`], which leaves the function masked on
/// purpose: the caller unmasks once every identity the table delivers has a
/// handler ([`crate::arch::riscv64::aia_imsic::claim_device_irqs_each`]), so
/// an interrupt can never arrive before there is something to receive it.
pub fn msix_unmask(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
) -> Result<(), crate::Error> {
    let cap_off = pci_capability_find(region, bus, device, function, cap_id::MSI_X)
        .ok_or(crate::Error::NotImplemented)?;
    // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
    // found on this function.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };
    let unmasked = (msix.message_control | (1u16 << 15)) & !(1u16 << 14);
    // SAFETY: as above — the message-control half of that same capability.
    unsafe {
        region.write_u16(bus, device, function, cap_off as u16 + 2, unmasked);
    }
    Ok(())
}

/// How many device MSIs have reached the probe's handler.
///
/// A device interrupt is otherwise invisible: the kernel claims it, finds no
/// handler, and counts it as spurious — "something fired and nobody knows
/// what".  This is what makes it say "the device fired".
static PROBE_MSI_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Receive one of them.
fn probe_msi_handler(irq: u32) {
    let seen = PROBE_MSI_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    if seen <= 8 {
        crate::println!(
            "[pci   ] RISC-V device MSI: irq {} claimed ({} since boot)",
            irq,
            seen
        );
    }
}

/// Write the message one of a device's table entries would write, and let the
/// dispatcher claim and deliver it.
///
/// The receive-side check a claim's owner runs against its own wiring: the
/// identity is made pending exactly as a device's table entry would make it,
/// and then claimed and dispatched exactly as the external-interrupt trap
/// would.  Answers whether the message reached a handler — an identity nobody
/// owns reaches nothing, and the kernel counts that as spurious, which is what
/// tells the two apart.
pub fn deliver_and_dispatch(irq: u32) -> bool {
    use crate::arch::riscv64::aia_imsic;

    if !aia_imsic::irq_has_handler(irq) {
        return false;
    }
    let spurious_before = crate::kernel::irq_stats::total_spurious();
    if !aia_imsic::deliver_message(irq) {
        return false;
    }
    let claimed = aia_imsic::handle_pending_external();
    claimed == irq && crate::kernel::irq_stats::total_spurious() == spurious_before
}

/// The identities this device's MSI-X table will deliver, if it has one.
///
/// Each entry delivers one identity, so the count is what a driver sizes its
/// claim by.  It comes from the capability alone — not from the controller the
/// entries will point at — which is what lets a driver claim at probe time and
/// leaves the *programming* to the step that runs once the IMSIC is up.
pub fn msix_entry_count(region: &EcamRegion, bus: u8, device: u8, function: u8) -> Option<u32> {
    let cap_off = pci_capability_find(region, bus, device, function, cap_id::MSI_X)?;
    // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
    // found on this function.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };
    if msix.message_control & (1u16 << 15) != 0 {
        // Already enabled: somebody owns it.
        return None;
    }
    Some(((msix.message_control & 0x07FF) as u32) + 1)
}

/// Whether a function's MSI-X capability is enabled.
///
/// The enable bit is what says the table has been programmed *and* somebody
/// took responsibility for it: a second claimant would move the identities out
/// from under the first one's handlers, and its waits would stop being
/// wakeable.
pub fn msix_enabled(region: &EcamRegion, bus: u8, device: u8, function: u8) -> bool {
    let Some(cap_off) = pci_capability_find(region, bus, device, function, cap_id::MSI_X) else {
        return false;
    };
    // SAFETY: `cap_off` is the offset of the MSI-X capability the walk just
    // found on this function.
    let msix = unsafe { pci_capability_msix(region, bus, device, function, cap_off) };
    msix.message_control & (1u16 << 15) != 0
}

/// A device's claim on the identities its MSI-X table will deliver.
///
/// The claim is taken at probe time, where the device is in hand, but the table
/// itself can only be programmed once the interrupt controller that carries the
/// messages is up — so the claim is what holds the two halves together.  It
/// carries the identity range the owner's handler is registered under, and
/// [`Self::arm`] writes that range into the device's table and lets the device
/// signal.  [`Self::is_armed`] is how the owner tells the difference, so a
/// completion path waits on the device only once the device can say something.
///
/// A claim is a handle: the owner keeps one, and the platform keeps another in
/// [`PENDING_MSIX`] until the table is programmed, which is why `arm` and
/// `is_armed` take `&self`.
#[derive(Clone)]
pub struct MsixClaim {
    inner: alloc::sync::Arc<MsixClaimInner>,
}

struct MsixClaimInner {
    first_irq: u32,
    count: u32,
    region: EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    armed: core::sync::atomic::AtomicBool,
}

impl MsixClaim {
    /// The first identity this device's table delivers.
    pub fn first_irq(&self) -> u32 {
        self.inner.first_irq
    }

    /// How many identities this device's table delivers.
    pub fn count(&self) -> u32 {
        self.inner.count
    }

    /// The function this claim is on, as it prints in a log.
    pub fn address(&self) -> (u8, u8, u8) {
        (self.inner.bus, self.inner.device, self.inner.function)
    }

    /// Whether the table has been programmed and the device let through.
    pub fn is_armed(&self) -> bool {
        self.inner.armed.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Program this device's table with the claimed identities, read it back,
    /// and only then let the device raise them.
    ///
    /// The function stays masked until the table has been read back, so an
    /// interrupt cannot arrive on an identity whose table entry was never
    /// written — a device nobody had a handler for is not a quiet device, it is
    /// one whose interrupts the kernel would count as spurious.
    pub fn arm(&self) -> Result<(), crate::Error> {
        use crate::arch::riscv64::aia_imsic;

        let inner = &self.inner;

        // Where each entry of this device's table is delivered.  Entries are
        // placed in turn over the harts that can receive, so a device with
        // several queues has them completed by different harts instead of all
        // by the boot hart.
        let mut targets = Vec::with_capacity(inner.count as usize);
        for index in 0..inner.count {
            let cpu = aia_imsic::msix_cpu_for_entry(index).ok_or(crate::Error::NotImplemented)?;
            targets.push(cpu);
        }

        let programmed = pci_enable_msix(
            &inner.region,
            inner.bus,
            inner.device,
            inner.function,
            inner.first_irq,
            &targets,
        )?;

        // Read the table back.  QEMU's devices decode their BAR, so the words
        // that went in are the words that come out; a table nobody wrote would
        // read as zeroes (or as a fault) and this is where that shows.
        let entry_bytes = core::mem::size_of::<aia_imsic::MsixTableEntry>();
        for index in 0..programmed.table_size {
            let Some(&target) = targets.get(index as usize) else {
                return Err(crate::Error::DeviceError);
            };
            let expected = aia_imsic::compose_msix_entry(target, inner.first_irq + index);
            let entry = programmed.table_phys as usize + index as usize * entry_bytes;
            if aia_imsic::read_msix_entry(entry) != expected {
                return Err(crate::Error::DeviceError);
            }
        }

        msix_unmask(&inner.region, inner.bus, inner.device, inner.function)?;
        inner
            .armed
            .store(true, core::sync::atomic::Ordering::Release);
        crate::println!(
            "[pci   ] RISC-V MSI-X {:02x}:{:02x}.{}: irq {}-{} placed on hart {:?}",
            inner.bus,
            inner.device,
            inner.function,
            inner.first_irq,
            inner.first_irq + inner.count - 1,
            targets
        );
        Ok(())
    }
}

/// Claim the identities this device's MSI-X table will deliver for `handler`.
///
/// The identities are allocated in the interrupt controller's table, which is
/// not the controller itself: this works at probe time, before the IMSIC is
/// initialised, and the table that will carry those identities is programmed
/// later by [`program_device_msix`].  Answers [`crate::Error::AlreadyExists`]
/// when the function's MSI-X is already enabled — see [`msix_enabled`] — and
/// [`crate::Error::NotImplemented`] when the function has no MSI-X at all.
pub fn claim_msix(
    region: &EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    named: &[(u16, crate::arch::riscv64::aia_imsic::IrqHandler)],
    fallback: &crate::arch::riscv64::aia_imsic::IrqHandler,
) -> Result<MsixClaim, crate::Error> {
    use crate::arch::riscv64::aia_imsic;

    if msix_enabled(region, bus, device, function) {
        return Err(crate::Error::AlreadyExists);
    }
    let count =
        msix_entry_count(region, bus, device, function).ok_or(crate::Error::NotImplemented)?;
    // One handler per identity: the entries the driver named for its queues,
    // and the device-wide one for every other entry the table can deliver.
    let handlers = crate::arch::platform::msix_handlers_for(count, named, fallback)
        .ok_or(crate::Error::InvalidArgument)?;
    let first_irq = aia_imsic::claim_device_irqs_each(&handlers)?;

    Ok(MsixClaim {
        inner: alloc::sync::Arc::new(MsixClaimInner {
            first_irq,
            count,
            region: *region,
            bus,
            device,
            function,
            armed: core::sync::atomic::AtomicBool::new(false),
        }),
    })
}

/// Claims taken before the interrupt controller was up, and the tables it owes.
///
/// A claim is registered here by the platform's hand-off to a driver
/// ([`crate::arch::platform::pci_claim_msix`]) and drained by
/// [`program_device_msix`], exactly once, when the controller can carry the
/// device's messages.  What the list holds is the *programming* a driver could
/// not do yet, not the ownership of the identities — that lives in the
/// interrupt controller's handler table, where a second claimant is refused.
static PENDING_MSIX: Mutex<Vec<MsixClaim>> = Mutex::new(Vec::new());

/// Hold `claim` until the interrupt controller can program its table.
pub fn defer_msix_arming(claim: MsixClaim) {
    PENDING_MSIX.lock().push(claim);
}

/// Walk a claim's receive side once, and say whether it reached its owner.
fn walk_receive_side(claim: &MsixClaim) -> bool {
    let irq = claim.first_irq();
    let reached = deliver_and_dispatch(irq);
    crate::println!(
        "[pci   ] RISC-V MSI receive side: irq {} {}",
        irq,
        if reached {
            "reached its handler"
        } else {
            "did not reach a handler"
        }
    );
    reached
}

/// Program and let through every MSI-X device that has an owner.
///
/// This runs once the interrupt controller is up, and it is what turns the
/// claims drivers took at probe time into live interrupts: every claim in
/// [`PENDING_MSIX`] gets its table programmed, is read back, and is unmasked,
/// and the receive side is then walked so the owner's own handler is the one
/// that runs.  A device nobody drives is claimed here too, by
/// [`probe_unclaimed_msix`], so the path is exercised at least once instead of
/// being code nobody runs.
///
/// Answers how many tables were armed.
pub fn program_device_msix() -> usize {
    let claims: Vec<MsixClaim> = PENDING_MSIX.lock().drain(..).collect();
    let mut armed = 0;

    for claim in &claims {
        let (bus, device, function) = claim.address();
        match claim.arm() {
            Ok(()) => {
                armed += 1;
                crate::println!(
                    "[pci   ] RISC-V MSI-X unmasked on {:02x}:{:02x}.{}: irq {}-{} belong to the driver that claimed them",
                    bus,
                    device,
                    function,
                    claim.first_irq(),
                    claim.first_irq() + claim.count() - 1
                );
                walk_receive_side(claim);
            }
            Err(error) => {
                // Say why: the interesting case is a device whose MSI-X table
                // has no address yet, because nothing assigned one.  QEMU boots
                // this kernel directly, with no firmware to run a PCI resource
                // pass, so a device's memory BARs read back as zero until
                // something assigns them — and an MSI-X table lives in a BAR.
                crate::println!(
                    "[pci   ] RISC-V MSI-X on {:02x}:{:02x}.{} not programmed: {} — a \
                     device whose BAR has no assigned address has no table to write",
                    bus,
                    device,
                    function,
                    error.as_str()
                );
            }
        }
    }

    armed + usize::from(probe_unclaimed_msix())
}

/// Program the first MSI-X-capable device, once the interrupt controller is up.
///
/// The boot enumerates its buses before the interrupt controller is
/// initialised, because drivers want the device list early — but an MSI-X
/// table is programmed *through* that controller, so the interrupt half has to
/// wait for it.  Re-walking the bus here costs a handful of config-space reads
/// and avoids threading the device list through the init sequence; the walk
/// itself is silent, so the boot still logs the devices once.
fn probe_unclaimed_msix() -> bool {
    use alloc::sync::Arc;

    let Some(region) = discover_ecam() else {
        return false;
    };
    let devices = enumerate(&region);
    let device = devices.iter().find(|d| {
        pci_capability_find(&region, d.bus, d.device, d.function, cap_id::MSI_X).is_some()
            && !msix_enabled(&region, d.bus, d.device, d.function)
    });
    let Some(device) = device else {
        return false;
    };

    // The boot's own walk of an unclaimed table registers one handler for the
    // whole device: nobody owns these identities, so there is no queue to
    // attribute them to.
    let probe_handler: crate::arch::riscv64::aia_imsic::IrqHandler = Arc::new(probe_msi_handler);
    let claim = match claim_msix(
        &region,
        device.bus,
        device.device,
        device.function,
        &[],
        &probe_handler,
    ) {
        Ok(claim) => claim,
        Err(error) => {
            crate::println!(
                "[pci   ] RISC-V MSI-X on {:02x}:{:02x}.{} not programmed: {} — a \
                 device whose BAR has no assigned address has no table to write",
                device.bus,
                device.device,
                device.function,
                error.as_str()
            );
            return false;
        }
    };
    if let Err(error) = claim.arm() {
        crate::println!(
            "[pci   ] RISC-V MSI-X on {:02x}:{:02x}.{} not programmed: {}",
            device.bus,
            device.device,
            device.function,
            error.as_str()
        );
        return false;
    }

    crate::println!(
        "[pci   ] RISC-V MSI-X probe: {} entries read back on {:02x}:{:02x}.{}",
        claim.count(),
        device.bus,
        device.device,
        device.function
    );
    crate::println!(
        "[pci   ] RISC-V MSI-X unmasked on {:02x}:{:02x}.{}: irq {}-{} have a handler",
        device.bus,
        device.device,
        device.function,
        claim.first_irq(),
        claim.first_irq() + claim.count() - 1
    );
    walk_receive_side(&claim)
}
