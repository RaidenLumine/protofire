//! src/arch/x86_64/msi.rs
//!
//! MSI/MSI-X interrupt composition and programming helpers for x86_64.
//!
//! Message Signalled Interrupts (MSI) allow PCI/PCIe devices to deliver
//! interrupts by writing to a special address range in the LAPIC MMIO
//! space, bypassing the IOAPIC entirely.
//!
//! ## MSI Address Format (x86_64)
//!
//! Bits 31:20 — 0xFEE (fixed)
//! Bits 19:12 — Destination ID (APIC ID << 4 for physical mode)
//! Bits 11:4  — Reserved (0)
//! Bits 3     — Redirection Hint (0)
//! Bits 2     — Destination Mode (0 = physical, 1 = logical)
//! Bits 1:0   — 0
//!
//! ## MSI Data Format (x86_64)
//!
//! Bits 15    — Extended Interrupt (0)
//! Bits 14    — Level (0 for edge-triggered on FSB interrupts)
//! Bits 13    — Reserved (0)
//! Bits 12    — Delivery Status (0)
//! Bits 10:8  — Delivery Mode (000 = Fixed, 001 = Lowest, 010 = SMI, 100 = NMI)
//! Bits 7:0   — Vector

// ---------------------------------------------------------------------------
// MSI composition
// ---------------------------------------------------------------------------

/// Delivery mode: Fixed.
pub const MSI_DELIVERY_FIXED: u32 = 0x00;
/// Delivery mode: Lowest Priority.
pub const MSI_DELIVERY_LOWEST: u32 = 0x01;

/// Compose the MSI message address for a given destination LAPIC ID.
///
/// Physical destination mode, no redirection.
pub fn msi_compose_address(dest_apic_id: u8) -> u32 {
    let dest = (dest_apic_id as u32 & 0xFF) << 12;
    0xFEE0_0000u32 | dest
}

/// Compose the MSI message data for a given vector and delivery mode.
///
/// Edge-triggered, no level.
pub fn msi_compose_data(vector: u8, delivery_mode: u32) -> u32 {
    (vector as u32 & 0xFF) | ((delivery_mode & 0x07) << 8)
}

// ---------------------------------------------------------------------------
// MSI-X BAR access helpers
// ---------------------------------------------------------------------------

/// An MSI-X table entry (16 bytes in device MMIO or memory).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MsixTableEntry {
    pub message_address_low: u32,
    pub message_address_high: u32,
    pub message_data: u32,
    pub vector_control: u32,
}

impl MsixTableEntry {
    /// Mask bit in the Vector Control field (bit 0).
    pub const MASK_BIT: u32 = 1;

    /// Returns `true` if the entry is masked.
    pub fn is_masked(&self) -> bool {
        self.vector_control & Self::MASK_BIT != 0
    }

    /// Construct a new masked entry (all zeros, masked).
    pub fn masked() -> Self {
        Self {
            message_address_low: 0,
            message_address_high: 0,
            message_data: 0,
            vector_control: Self::MASK_BIT,
        }
    }
}

/// Set up an MSI-X table entry for a given vector and destination.
///
/// The entry comes back **masked**.  A table entry is live as soon as it is
/// written, and the vector in `data` is one the caller has usually not
/// finished preparing for — so the mask is what keeps a half-programmed
/// entry from raising an interrupt, and unmasking is a separate, deliberate
/// step once the rest of the device is ready.
pub fn msix_compose_entry(dest_apic_id: u8, vector: u8, delivery_mode: u32) -> MsixTableEntry {
    MsixTableEntry {
        message_address_low: msi_compose_address(dest_apic_id),
        message_address_high: 0,
        message_data: msi_compose_data(vector, delivery_mode),
        vector_control: MsixTableEntry::MASK_BIT,
    }
}

// ---------------------------------------------------------------------------
// MSI-X claims
// ---------------------------------------------------------------------------

// The claim below programs a device's table, which means configuration space,
// MMIO and a machine that is up — none of which a host build has.  The window
// and its predicates are not gated: the trap handler names them on every
// x86_64 configuration.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::sync::Arc;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use alloc::vec::Vec;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::AtomicBool;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use core::sync::atomic::Ordering;

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::irq_handlers::IrqHandler;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::pci::cap_id::MSI_X;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::pci_capability_find;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::pci_capability_msix;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::pci_config_write_u16;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::pci_enumerate_buses;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::arch::x86_64::pci::PciAddress;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::kernel::sync::SpinLock;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use crate::Error;

/// The window of IDT vectors a device's MSI-X table may name.
///
/// The fixed assignments stop at `VIRTIO_QUEUE_VECTOR` and the vector comment
/// in `interrupts.rs` reserves 34-127, so this window sits above both.  It is
/// the *identity* space as well: [`crate::arch::irq_handlers`] is indexed from
/// [`MSIX_HANDLER_BASE`], so a vector and the handler that answers it are the
/// same number, which is the arrangement the ITS and the IMSIC already use.
pub const MSIX_VECTOR_BASE: u8 = 0x60;
/// The last vector a device's table may name.
///
/// The window is sized for more than one claim at a time: a claim takes one
/// identity per table entry its driver *names* ([RFC 0005], which left every
/// unnamed entry unable to deliver), and the machine's claimants — a NIC's
/// two queues, a block device's one — name a handful between them.  The top
/// of the window is the top of the range `interrupts.rs` reserves for device
/// vectors.
///
/// [RFC 0005]: ../../../docs/rfcs/0005-claim-the-msix-entries-a-driver-names.md
pub const MSIX_VECTOR_LAST: u8 = 0x7F;
// The window belongs inside the range `interrupts.rs` reserves for device
// vectors (34-127) and above the fixed assignments, or a device's message
// could land on the timer.
const _: () = assert!(MSIX_VECTOR_BASE >= 34);
const _: () = assert!(MSIX_VECTOR_LAST <= 127);
const _: () = assert!(MSIX_VECTOR_BASE > crate::arch::x86_64::interrupts::VIRTIO_QUEUE_VECTOR);
const _: () = assert!(MSIX_VECTOR_LAST > MSIX_VECTOR_BASE);
/// The identity the handler registry's window starts at on this machine.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) const MSIX_HANDLER_BASE: u32 = MSIX_VECTOR_BASE as u32;

// The two control words a claim passes through live in `crate::arch::pci`,
// because the same order has to hold on every machine that programs an MSI-X
// table — and this is one of them.  Every use is the claim path (or its
// tests), which a host build does not compile.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
use crate::arch::pci::armed_control;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
use crate::arch::pci::claimed_control;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "none")))]
use crate::arch::pci::MSIX_ENABLE;

/// Whether `vector` is one a device's MSI-X table may deliver.
pub const fn is_msix_vector(vector: u8) -> bool {
    vector >= MSIX_VECTOR_BASE && vector <= MSIX_VECTOR_LAST
}

/// A PCIe function's claim on the vectors its MSI-X table will deliver.
///
/// The claim is taken at probe time, where the device is in hand, and does
/// two things then: it registers the handlers in the identity registry and it
/// enables the capability with the function mask set (see [`claimed_control`]).
/// The table can only be programmed once the local APIC is up — so the claim
/// is what holds the two halves together.  [`Self::arm`] writes the identities
/// into the function's table and clears the mask; [`Self::is_armed`] is how
/// the owner tells the difference, so a completion path waits on the device
/// only once the device can say something.
#[derive(Clone)]
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) struct MsixClaim {
    inner: Arc<MsixClaimInner>,
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
struct MsixClaimInner {
    /// The function the table belongs to.
    address: PciAddress,
    /// Where the table is reached in kernel virtual memory.
    table: *mut MsixTableEntry,
    /// The MSI-X capability's offset in the function's configuration space,
    /// where the message-control half has to be written for it to signal.
    capability_offset: u8,
    /// Message Control as it was found, before this claim turned MSI-X on.
    message_control: u16,
    /// The entries the function's table has.
    count: u32,
    /// The first vector this claim took.
    first_vector: u8,
    /// The table entries this claim owns, in vector order: `entries[i]` is
    /// delivered on `first_vector + i`.  Every other entry of the table is
    /// written masked, because the device would otherwise be free to deliver
    /// an identity this claim never took.
    entries: Vec<u16>,
    /// Whether the table has been written and the function let through.
    armed: AtomicBool,
}

// SAFETY: the claim names one function's own table — device MMIO, which any
// CPU may write — and the vectors it owns.  Moving it between threads moves
// the only handle to that table.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Send for MsixClaimInner {}
// SAFETY: as the `Send` impl above; the table pointer is never aliased by a
// second claim, because a claim is refused when the function's MSI-X is
// already enabled.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe impl Sync for MsixClaimInner {}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl MsixClaim {
    /// The first interrupt identity this function's table delivers.
    ///
    /// Zero when the machine gave the function no identity at all — identity 0
    /// is not an interrupt, so it can stand for "none".
    pub(crate) fn first_irq(&self) -> u32 {
        self.inner.first_vector as u32
    }

    /// Whether the table has been programmed and the function let through.
    pub(crate) fn is_armed(&self) -> bool {
        self.inner.armed.load(Ordering::Acquire)
    }

    /// Write the entries into this function's table and let it signal.
    fn arm(&self) -> Result<(), Error> {
        // The whole table is written, and every entry comes out of this step
        // masked: the owned ones carry a composed message, and the rest carry
        // the mask and nothing else — which is what makes "nobody owns this
        // entry" the same thing as "this entry cannot deliver".
        for entry_index in 0..self.inner.count {
            let entry = match self
                .inner
                .entries
                .iter()
                .position(|entry| *entry as u32 == entry_index)
            {
                Some(index) => msix_compose_entry(
                    destination_apic_id(index as u32),
                    self.inner.first_vector + index as u8,
                    MSI_DELIVERY_FIXED,
                ),
                None => MsixTableEntry::masked(),
            };
            // SAFETY: `entry_index` is inside the table this claim mapped,
            // which is `count` entries wide.
            unsafe { write_entry(self.inner.table.add(entry_index as usize), entry) };
        }

        // Make the writes visible, then let the owned entries through.  They
        // are inert until this step, which is why it is separate.
        core::sync::atomic::fence(Ordering::SeqCst);
        for entry in &self.inner.entries {
            // SAFETY: as the loop above — the same table, and an entry this
            // claim owns.
            unsafe { unmask_entry(self.inner.table.add(*entry as usize)) };
        }
        core::sync::atomic::fence(Ordering::SeqCst);

        // Clear the function mask: the one bit between a programmed table and
        // a device that may signal.  MSI-X itself was enabled when the claim
        // was taken (see `claimed_control`), so this is the second half of
        // that step, not an enable — the entries are unmasked and the table
        // read back before it, and it belongs to the capability's
        // message-control half rather than to a table entry, which is why it
        // is the last thing this does.
        let control = armed_control(self.inner.message_control);
        // SAFETY: the message-control half of the MSI-X capability this claim
        // located, inside the function's own configuration space.
        unsafe {
            pci_config_write_u16(
                self.inner.address,
                self.inner.capability_offset + 2,
                control,
            );
        }

        self.inner.armed.store(true, Ordering::Release);
        Ok(())
    }
}

/// Whether a claim that names `entries` table entries fits the vector window.
///
/// The bound is on the entries the driver names, because the identities are
/// what consume vectors — one per named entry.  It is deliberately *not* a
/// bound on the table's size: an unnamed entry is written masked by
/// [`MsixClaim::arm`], so a table wider than the window (an NVMe controller's
/// has sixty-five entries against the window's thirty-two vectors) can still
/// be claimed for the one entry a completion queue uses.  This was a
/// table-width bound once, and it refused the NVMe claimant outright.
pub const fn claim_window_fits(entries: usize) -> bool {
    entries <= (MSIX_VECTOR_LAST - MSIX_VECTOR_BASE + 1) as usize
}

/// Claim the vectors this function's MSI-X table will deliver.
///
/// Answers [`Error::NotImplemented`] when the function has no MSI-X capability,
/// [`Error::AlreadyExists`] when somebody has already enabled it, and
/// [`Error::NoSpace`] when the vector window cannot hold the run — in every one
/// of those the caller stays on the polling path it has today.
///
/// The claim **enables MSI-X with the function mask set**: from here the
/// capability reads as on — which a device may consult while it is being
/// configured, and an NVMe controller does when a `Create I/O Completion
/// Queue` command names its vector — while nothing can be delivered, because
/// the mask holds every table entry back and the table itself is still the
/// masked one it reset to.  [`MsixClaim::arm`] is where the table is
/// programmed and the mask cleared, once the machine can receive.
///
/// # Safety
///
/// `address` must name a function this machine enumerated.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) unsafe fn claim_msix(
    address: PciAddress,
    named: &[(u16, IrqHandler)],
) -> Result<MsixClaim, Error> {
    let offset = pci_capability_find(address, MSI_X).ok_or(Error::NotImplemented)?;
    // SAFETY: `offset` names this function's MSI-X capability, which
    // `pci_capability_find` just located in its configuration space.
    let capability = unsafe { pci_capability_msix(address, offset) };
    if capability.message_control & MSIX_ENABLE != 0 {
        return Err(Error::AlreadyExists);
    }

    let count = ((capability.message_control & 0x07FF) as u32) + 1;
    if !claim_window_fits(named.len()) {
        return Err(Error::InvalidArgument);
    }

    // One identity per entry the driver names — and no identity for the rest,
    // which `arm` writes masked.  The claim is the driver's requirement, not
    // the table's size: an xHCI controller with sixteen interrupters and one
    // in use takes one vector, not sixteen.
    let handlers =
        crate::arch::platform::msix_named_handlers(count, named).ok_or(Error::InvalidArgument)?;
    let first = crate::arch::irq_handlers::claim_each(
        MSIX_HANDLER_BASE,
        MSIX_VECTOR_BASE as u32,
        MSIX_VECTOR_LAST as u32,
        &handlers,
    )?;
    // Table entry `entries[i]` is delivered on vector `first + i`.
    let entries: Vec<u16> = named.iter().map(|(entry, _)| *entry).collect();

    // The table lives in one of the function's BARs: the capability names the
    // BAR by indicator and the offset inside it.
    let bar_index = (capability.table_bir_and_offset & 0x7) as usize;
    let table_offset = (capability.table_bir_and_offset & !0x7) as usize;
    let devices = pci_enumerate_buses();
    let device = devices
        .iter()
        .find(|device| {
            device.bus == address.bus
                && device.device == address.device
                && device.function == address.function
        })
        .ok_or(Error::NotFound)?;
    let bar = device.bars.get(bar_index).ok_or(Error::InvalidArgument)?;
    if !bar.is_mmio || bar.base_address == 0 {
        return Err(Error::InvalidArgument);
    }

    let table_bytes = count as usize * core::mem::size_of::<MsixTableEntry>();
    let table_phys = bar.base_address + table_offset as u64;
    // SAFETY: the BAR is a live MMIO range the enumeration decoded, and the
    // table lies inside it.
    let table = unsafe { crate::arch::mmu::map_device_mmio(table_phys, table_bytes) }
        .ok_or(Error::DeviceError)? as *mut MsixTableEntry;

    // Let the device see the capability as enabled, with everything held back.
    // This is the last fallible step's aftermath, so a claim that failed above
    // leaves the function exactly as it found it.
    // SAFETY: the message-control half of the MSI-X capability located above,
    // inside the function's own configuration space.
    unsafe {
        pci_config_write_u16(
            address,
            offset + 2,
            claimed_control(capability.message_control),
        );
    }

    Ok(MsixClaim {
        inner: Arc::new(MsixClaimInner {
            address,
            table,
            capability_offset: offset,
            message_control: capability.message_control,
            count,
            first_vector: first as u8,
            entries,
            armed: AtomicBool::new(false),
        }),
    })
}

/// Claims waiting for the local APIC to be up.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
static PENDING: SpinLock<Vec<MsixClaim>> = SpinLock::new(Vec::new());

/// Hold a claim until the local APIC can carry what it will deliver.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn defer_msix_arming(claim: MsixClaim) {
    PENDING.lock().push(claim);
}

/// Program every claimed table, now that the machine can receive.
///
/// Answers how many functions were armed.  One whose programming fails is not
/// armed and says so; its owner's completion path sees
/// [`MsixClaim::is_armed`] answer `false` and polls, which is the same path it
/// would have taken on a machine with no MSI-X at all.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn program_device_msix() -> usize {
    let claims: Vec<MsixClaim> = PENDING.lock().drain(..).collect();
    let mut armed = 0;
    for claim in &claims {
        let address = claim.inner.address;
        match claim.arm() {
            Ok(()) => {
                armed += 1;
                let placement: Vec<u32> = (0..claim.inner.entries.len() as u32)
                    .map(destination_cpu)
                    .collect();
                crate::println!(
                    "[msix  ] MSI-X on {:02x}:{:02x}.{} delivers vectors {}..{} on table \
                     entries {:?}, placed on cpus {:?}",
                    address.bus,
                    address.device,
                    address.function,
                    claim.inner.first_vector,
                    claim.inner.first_vector as u32 + claim.inner.entries.len() as u32 - 1,
                    claim.inner.entries,
                    placement
                );
            }
            Err(error) => {
                crate::println!(
                    "[msix  ] MSI-X on {:02x}:{:02x}.{} not programmed ({:?}); its driver polls",
                    address.bus,
                    address.device,
                    address.function,
                    error
                );
            }
        }
    }
    armed
}

/// Run the handler the vector's identity was claimed with.
///
/// Answers whether a handler ran; a vector in the window that nobody claimed is
/// the trap's to account for, as spurious.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub(crate) fn dispatch_vector(vector: u8) -> bool {
    crate::arch::irq_handlers::dispatch(MSIX_HANDLER_BASE, vector as u32)
}

/// Nothing to dispatch off bare metal: a host build has no device tables and
/// no IDT of this shape.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
pub(crate) fn dispatch_vector(_vector: u8) -> bool {
    false
}

/// Which CPU's local APIC an entry's message should name.
///
/// Round-robin over the CPUs the machine has online, the same rule RFC 0001
/// chose for the device-tree machines: a device whose table has four entries
/// puts them on four CPUs in turn rather than serialising every completion on
/// the boot processor.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn destination_apic_id(index: u32) -> u8 {
    let cpu = destination_cpu(index);
    crate::arch::x86_64::irq_balance::lapic_id_of(cpu)
        .unwrap_or_else(|| crate::arch::x86_64::apic::lapic_id() as u8)
}

/// The CPU entry `index`'s message is placed on: the CPUs in turn.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn destination_cpu(index: u32) -> u32 {
    index % crate::kernel::smp::online_cpu_count().max(1)
}

/// Write one 16-byte table entry.
///
/// # Safety
///
/// `entry` must point at an MSI-X table entry this kernel mapped.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn write_entry(entry: *mut MsixTableEntry, value: MsixTableEntry) {
    // SAFETY: the caller's contract says `entry` names a table entry; each
    // field is a 32-bit register of that entry.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entry).message_address_low),
            value.message_address_low,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entry).message_address_high),
            value.message_address_high,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entry).message_data),
            value.message_data,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entry).vector_control),
            value.vector_control,
        );
    }
}

/// Let one table entry through: clear its mask bit, leaving the rest of the
/// entry alone.
///
/// # Safety
///
/// As [`write_entry`]: `entry` must point at a table entry this kernel mapped,
/// whose message fields have already been written.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
unsafe fn unmask_entry(entry: *mut MsixTableEntry) {
    // SAFETY: `entry` names a mapped table entry, and Vector Control is the
    // entry's fourth register.
    let control = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*entry).vector_control)) };
    // SAFETY: as the read above — the same register, with the mask cleared.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*entry).vector_control),
            control & !MsixTableEntry::MASK_BIT,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_address_for_lapic_id_0() {
        assert_eq!(msi_compose_address(0), 0xFEE0_0000);
    }

    #[test]
    fn msi_address_for_lapic_id_1() {
        assert_eq!(msi_compose_address(1), 0xFEE0_1000);
    }

    #[test]
    fn msi_data_vector_32_fixed() {
        let data = msi_compose_data(32, MSI_DELIVERY_FIXED);
        assert_eq!(data & 0xFF, 32);
        assert_eq!((data >> 8) & 0x07, MSI_DELIVERY_FIXED);
    }

    #[test]
    fn msix_entry_is_masked() {
        let entry = MsixTableEntry::masked();
        assert!(entry.is_masked());
    }

    #[test]
    fn msix_entry_compose() {
        let entry = msix_compose_entry(0, 44, MSI_DELIVERY_FIXED);
        // Masked until the caller says otherwise: see the function's note.
        assert!(entry.is_masked());
        assert_eq!(entry.message_address_low, 0xFEE0_0000);
        assert_eq!(entry.message_data & 0xFF, 44);
    }

    #[test]
    fn msix_vector_window_is_closed_at_both_ends() {
        for vector in MSIX_VECTOR_BASE..=MSIX_VECTOR_LAST {
            assert!(is_msix_vector(vector), "vector {vector} is in the window");
        }
        assert!(!is_msix_vector(MSIX_VECTOR_BASE - 1));
        assert!(!is_msix_vector(MSIX_VECTOR_LAST + 1));
    }

    #[test]
    fn msix_window_stub_answers_every_vector_in_the_window() {
        for vector in MSIX_VECTOR_BASE as usize..=MSIX_VECTOR_LAST as usize {
            assert!(
                crate::arch::x86_64::idt::types::msix_window_stub(vector).is_some(),
                "vector {vector} needs a stub of its own"
            );
        }
        assert!(
            crate::arch::x86_64::idt::types::msix_window_stub(MSIX_VECTOR_BASE as usize - 1)
                .is_none()
        );
    }

    /// The window bounds the entries a driver *names*, not the table's size.
    ///
    /// The two were the same check once, and the table's width was what it
    /// weighed — so a controller whose table is wider than the window could
    /// not be claimed at all even for the one entry its driver used, which is
    /// exactly what an NVMe controller is (65 entries, one completion queue).
    #[test]
    fn msix_window_bounds_named_entries_not_the_table() {
        assert!(claim_window_fits(1));
        assert!(claim_window_fits(32));
        assert!(!claim_window_fits(33));
    }

    /// The two message-control words a claim passes through.
    ///
    /// `claimed_control` turns MSI-X on with the function mask set — the
    /// state a device reads while it is being configured (an NVMe controller
    /// decides a completion queue's interrupt behaviour `Create I/O
    /// Completion Queue` time) while nothing can be delivered — and
    /// `armed_control` clears the mask, which is the only bit between a
    /// programmed table and a signalling device.
    #[test]
    fn msix_claim_control_words_enable_without_delivering() {
        use crate::arch::pci::MSIX_FUNCTION_MASK;

        assert_eq!(claimed_control(0), MSIX_ENABLE | MSIX_FUNCTION_MASK);
        assert_eq!(armed_control(0), MSIX_ENABLE);
        // Other capability bits (the table's size, for one) survive both.
        assert_eq!(
            claimed_control(0x0400),
            0x0400 | MSIX_ENABLE | MSIX_FUNCTION_MASK
        );
        assert_eq!(armed_control(0x0400), 0x0400 | MSIX_ENABLE);
        // Either word from either starting state ends enabled; only the mask
        // separates them.
        assert_eq!(
            claimed_control(MSIX_ENABLE),
            MSIX_ENABLE | MSIX_FUNCTION_MASK
        );
        assert_eq!(armed_control(MSIX_FUNCTION_MASK), MSIX_ENABLE);
    }
}
