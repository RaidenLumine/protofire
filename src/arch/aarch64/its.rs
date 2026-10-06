//! src/arch/aarch64/its.rs
//!
//! ARM GICv3 Interrupt Translation Service: the bridge from a PCIe device's
//! message to an LPI.
//!
//! A device signals by writing four bytes into memory — the address its MSI-X
//! table entry names, carrying the event in the data word.  On this
//! architecture that write lands on the ITS: the top half of the address names
//! the device, the data names an event on it, and the ITS looks the pair up in
//! a table the kernel gave it and delivers the LPI that entry names.  Nothing
//! else in the kernel has to be told a message arrived, and nothing else has to
//! poll for one.
//!
//! What lives here:
//!
//! - The ITS itself: its command queue, the device and collection tables, and
//!   the commands that fill them (`MAPD`, `MAPC`, `MAPTI`, `INV`, `SYNC`).
//! - The per-device translation tables (`ITT`), which are what an EventID is
//!   translated through, and which have to outlive the mapping that names them.
//! - The driver-facing half of a PCIe function's MSI-X claim: which LPIs its
//!   table will deliver ([`claim_msix`]), and the programming of the table
//!   itself ([`MsixClaim::arm`]) once the controller is up.
//!
//! The identities themselves are the shared ones in
//! [`crate::arch::irq_handlers`]; the LPI tables a redistributor reads are the
//! GIC's, and live in [`super::gicv3`].
//!
//! References:
//!
//! - ARM IHI 0069, *Architecture Specification: GICv3 and GICv4*, chapter 5
//!   (the ITS: `GITS_*`, the command queue) and chapter 6 (LPIs).
//! - Linux `drivers/irqchip/irq-gic-v3-its.c` — the bring-up order, the command
//!   encodings, and the table-alignment rules this follows.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use super::gicv3;
use super::mmio::dsb_sy;
use super::mmio::read_u32;
use super::mmio::read_u64;
use super::mmio::write_u32;
use super::mmio::write_u64;
use crate::arch::irq_handlers;
use crate::arch::irq_handlers::IrqHandler;
use crate::arch::pci;
use crate::arch::pci::ConfigSpace;
use crate::kernel::sync::SpinLock;
use crate::memory::dma::DmaBuffer;
use crate::memory::frame::FRAME_SIZE;
use crate::Error;

// -- The ITS register block -----------------------------------------------

const GITS_CTLR: usize = 0x0000;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;

/// The window a device's message lands in.
///
/// The ITS reads the DeviceID from the half of the address above this one and
/// the EventID from the data the device wrote, which is why an MSI-X table
/// entry built for this machine carries both.
pub(crate) const GITS_TRANSLATER: usize = 0x1_0040;

/// QEMU `virt` places the ITS here when the device tree does not say.
const GITS_BASE_DEFAULT: usize = 0x0808_0000;

const GITS_CTLR_ENABLE: u32 = 1 << 0;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;

/// `GITS_TYPER.PTA`: whether a collection names a redistributor by its
/// physical address or by a linear processor number.
const GITS_TYPER_PTA: u64 = 1 << 19;

const GITS_BASER_VALID: u64 = 1 << 63;
const GITS_BASER_TYPE_SHIFT: u64 = 56;
const GITS_BASER_ENTRY_SIZE_SHIFT: u64 = 48;
const GITS_BASER_PAGE_SIZE_SHIFT: u64 = 8;
const GITS_BASER_INNER_CACHEABLE: u64 = 7 << 59;
const GITS_BASER_INNER_NON_CACHEABLE: u64 = 1 << 59;
const GITS_BASER_INNER_SHAREABLE: u64 = 3 << 10;
const GITS_BASER_INNER_CACHEABLE_MASK: u64 = 7 << 59;
const GITS_BASER_SHAREABLE_MASK: u64 = 3 << 10;
/// Bits [51:12] of the table address; the low twelve are the page offset.
const GITS_BASER_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const GITS_CBASER_VALID: u64 = 1 << 63;

/// Table types the ITS knows, from the `GITS_BASER<n>.TYPE` field.
///
/// The type is not the register's index: the controller decides which
/// `GITS_BASER<n>` holds which table, and reports it there.  The kernel reads
/// each register's type and uses the one that answers.
const GITS_TABLE_DEVICE: u64 = 1;
const GITS_TABLE_COLLECTION: u64 = 4;
const GITS_BASER_COUNT: usize = 8;

/// The ITS's DeviceID space this kernel is willing to size a table for.
///
/// The device table holds one 8-byte entry per DeviceID the ITS can name, so a
/// machine reporting a 16-bit space wants 512 KiB for it.  A machine reporting
/// more is capped here and says so: nothing this kernel enumerates has a
/// DeviceID above that, and a boot should not spend megabytes on a table it
/// will never index.
const DEVICE_ID_BITS_MAX: u32 = 16;

// -- The command queue ----------------------------------------------------

/// Commands are 32 bytes, and the queue the ITS reads them from is 64 KiB —
/// the size the architecture fixes for it, and the amount of RAM it costs.
const COMMAND_BYTES: usize = 32;
const COMMAND_QUEUE_BYTES: usize = 0x1_0000;

const COMMAND_MAPD: u8 = 0x08;
const COMMAND_MAPC: u8 = 0x09;
const COMMAND_MAPTI: u8 = 0x0a;
const COMMAND_INV: u8 = 0x0c;
const COMMAND_SYNC: u8 = 0x05;
const COMMAND_INT: u8 = 0x03;

/// Events one device's translation table holds.
///
/// A device's MSI-X table can name 2048 vectors; this kernel gives the
/// translation table 256 entries, which the command's size field expresses as
/// a power of two, and refuses a device that asks for more.  QEMU's
/// `virtio-net-pci` asks for two.
const EVENT_COUNT: u32 = 256;
const EVENT_BITS: u32 = 8;
const ITT_BYTES: usize = EVENT_COUNT as usize * 8;

/// One ITS command: four 64-bit words the ITS parses.
type Command = [u64; 4];

/// The address bits a command carries, with the low bits the register does not
/// hold cleared.
///
/// An ITT address starts at bit 8 of the command word and a collection's
/// target at bit 16, so the same address encodes two ways depending on the
/// field it goes into.
fn address_field(address: u64, low_bits: u32) -> u64 {
    address & GITS_BASER_ADDRESS_MASK & !((1_u64 << low_bits) - 1)
}

fn command_mapd(device_id: u32, itt: usize) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_MAPD as u64 | ((device_id as u64) << 32);
    // The size field is log2 of the translation table's entries, minus one.
    command[1] = (EVENT_BITS - 1) as u64;
    command[2] = address_field(itt as u64, 8) | (1 << 63);
    command
}

fn command_mapc(collection: u16, target: u64) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_MAPC as u64;
    command[2] = target | collection as u64 | (1 << 63);
    command
}

fn command_mapti(device_id: u32, event_id: u32, lpi: u32, collection: u16) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_MAPTI as u64 | ((device_id as u64) << 32);
    command[1] = event_id as u64 | ((lpi as u64) << 32);
    command[2] = collection as u64;
    command
}

fn command_inv(device_id: u32, event_id: u32) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_INV as u64 | ((device_id as u64) << 32);
    command[1] = event_id as u64;
    command
}

fn command_sync(target: u64) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_SYNC as u64;
    command[2] = target;
    command
}

/// Ask the ITS to translate an event as if its device had written it.
///
/// The command exists for exactly this: software wants to raise a
/// message-signalled interrupt without a device, and the ITS runs the same
/// translation and the same delivery a real write would.
fn command_int(device_id: u32, event_id: u32) -> Command {
    let mut command = [0_u64; 4];
    command[0] = COMMAND_INT as u64 | ((device_id as u64) << 32);
    command[1] = event_id as u64;
    command
}

/// The target field a `MAPC` — and the `SYNC` that waits for it — carries for
/// one redistributor.
///
/// The architecture lets a controller choose what a collection names: bit 19
/// of `GITS_TYPER` says whether the field is the redistributor's physical
/// address or a linear processor number, and the number, when that is what it
/// wants, comes from the redistributor itself.  Getting this wrong is not a
/// subtle failure — the command is rejected and every interrupt the
/// collection would have carried is lost — so it is read from the controller
/// rather than assumed.
fn collection_target(base: usize, rd_base: usize) -> u64 {
    if read_u64(base + GITS_TYPER) & GITS_TYPER_PTA != 0 {
        address_field(rd_base as u64, 16)
    } else {
        (gicv3::processor_number(rd_base) as u64) << 16
    }
}

// -- The ITS --------------------------------------------------------------

/// Everything the ITS needs to keep alive between commands.
struct ItsState {
    /// The register block.
    base: usize,
    /// The command queue, and the byte offset of the next command in it.
    commands: DmaBuffer,
    writer: usize,
    /// One entry per DeviceID the ITS can name.
    device_table: DmaBuffer,
    /// One entry per collection.
    collections: DmaBuffer,
    /// Translation tables for the devices that were mapped, kept because the
    /// device table still points at them.
    translation_tables: Vec<DmaBuffer>,
    /// The DeviceID bits the device table covers.
    device_id_bits: u32,
}

static ITS_STATE: SpinLock<Option<ItsState>> = SpinLock::new(None);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The collection a CPU's messages are delivered to.
///
/// A collection is a name in the collection table whose entry holds a
/// redistributor address, and this kernel maps one per CPU: collection `n` is
/// CPU `n`'s redistributor.  Making the two numbers the same is what lets a
/// placement name a CPU and have the mapping follow it without a second table
/// to search.
const fn collection_for_cpu(cpu: u32) -> u16 {
    cpu as u16
}

/// The LPIs a device may be given.
///
/// The two ends of the window are left alone: identity 0 is the registry's
/// "no device owns this" slot, and the last one is where a boot-time self-test
/// would live if this machine needed one.
const FIRST_DEVICE_LPI: u32 = gicv3::LPI_BASE + 1;
const LAST_DEVICE_LPI: u32 = gicv3::LPI_LAST - 1;

/// The LPI the boot's own delivery test uses.
///
/// It is the registry's first slot, and no device is ever given it — device
/// identities start at [`FIRST_DEVICE_LPI`] — so the message this test leaves
/// behind can never be mistaken for one a driver is waiting on.
const SELF_TEST_LPI: u32 = gicv3::LPI_BASE;

/// The DeviceID the self-test maps for itself.
///
/// PCIe bus 0, device 0, function 0 is the host bridge: it has no MSI-X and
/// claims nothing, so the mapping cannot collide with a device's.
const SELF_TEST_DEVICE_ID: u32 = 0;

/// The frames a byte count needs, rounded up.
fn frames_for(bytes: usize) -> usize {
    bytes.div_ceil(FRAME_SIZE)
}

/// The ITS's register block, when this machine has one.
///
/// Two things have to be true: the interrupt controller has to be a GICv3
/// (a GICv2 machine has no ITS to point at), and the machine has to have
/// described one.  A machine that fails either is a machine whose PCIe devices
/// complete by polling, which is the answer this returns `None` for.
fn its_base() -> Option<usize> {
    if !super::interrupt_controller::is_v3() {
        return None;
    }
    Some(
        crate::arch::fdt::platform_info()
            .its_base
            .unwrap_or(GITS_BASE_DEFAULT),
    )
}

impl ItsState {
    /// Wait until the queue has room for one more command.
    fn make_room(&self) -> bool {
        let next = (self.writer + COMMAND_BYTES) % COMMAND_QUEUE_BYTES;
        for _ in 0..1_000_000 {
            if read_u64(self.base + GITS_CREADR) as usize != next {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Put one command in the queue and tell the ITS where the queue ends.
    fn submit(&mut self, command: Command) -> Result<(), Error> {
        if !self.make_room() {
            return Err(Error::Busy);
        }

        let offset = self.writer;
        // SAFETY: the command queue owns `COMMAND_QUEUE_BYTES` bytes, `offset`
        // is always a multiple of `COMMAND_BYTES` inside it, and four 64-bit
        // words fit before the end of the queue because a command is exactly
        // that long.
        unsafe {
            let words = self.commands.as_ptr().add(offset) as *mut u64;
            for (index, word) in command.iter().enumerate() {
                words.add(index).write_volatile(*word);
            }
        }

        self.writer = (offset + COMMAND_BYTES) % COMMAND_QUEUE_BYTES;
        // The ITS reads the queue from memory; the barrier is what makes the
        // words above visible before the write pointer that publishes them.
        dsb_sy();
        write_u64(self.base + GITS_CWRITER, self.writer as u64);
        Ok(())
    }

    /// Whether the ITS has consumed every command up to `marker`.
    fn wait_for_completion(&self, marker: usize) -> bool {
        for _ in 0..1_000_000 {
            if read_u64(self.base + GITS_CREADR) as usize == marker {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Run a `SYNC` and wait for the commands before it to complete.
    fn sync(&mut self, target: u64) -> Result<(), Error> {
        self.submit(command_sync(target))?;
        if !self.wait_for_completion(self.writer) {
            return Err(Error::DeviceError);
        }
        Ok(())
    }

    /// Map one device's translation table and the events it will deliver.
    fn map_device(
        &mut self,
        device_id: u32,
        first_lpi: u32,
        count: u32,
        collections: &[u16],
        sync_targets: &[u64],
    ) -> Result<(), Error> {
        if device_id >= (1_u32 << self.device_id_bits) {
            return Err(Error::InvalidArgument);
        }
        if collections.len() != count as usize {
            return Err(Error::InvalidArgument);
        }

        let table = DmaBuffer::allocate(frames_for(ITT_BYTES)).ok_or(Error::NoSpace)?;
        self.submit(command_mapd(device_id, table.phys_addr()))?;

        for index in 0..count {
            // The EventID is what the device's MSI-X table entry names as its
            // data word; the LPI is where the message ends up.  Making them
            // the same number below `first_lpi` would be a lie about a device
            // that names a table the kernel did not write, so the pair is
            // mapped explicitly, entry by entry — including the collection,
            // which is where this entry's interrupts land.
            let event_id = index;
            self.submit(command_mapti(
                device_id,
                event_id,
                first_lpi + index,
                collections[index as usize],
            ))?;
            // A translation the ITS cached before this mapping would deliver
            // the old LPI; the invalidate is what retires it.
            self.submit(command_inv(device_id, event_id))?;
        }

        // One SYNC per redistributor the mapping above can now deliver to: the
        // command only reaches the queues of the target it names.
        for target in sync_targets {
            self.sync(*target)?;
        }

        // Only now is the table safe to keep: the ITS holds its physical
        // address, and the mapping that names it must outlive the commands.
        self.translation_tables.push(table);
        Ok(())
    }

    /// Map one collection onto a CPU's redistributor.
    fn map_collection(&mut self, collection: u16, rd_base: usize) -> Result<(), Error> {
        let target = collection_target(self.base, rd_base);
        self.submit(command_mapc(collection, target))?;
        self.sync(target)
    }
}

/// Bring the ITS up and map the one collection this kernel uses.
fn build(base: usize) -> Result<ItsState, Error> {
    let typer = read_u64(base + GITS_TYPER);
    let device_id_bits = ((((typer >> 13) & 0x1f) + 1).min(DEVICE_ID_BITS_MAX as u64)) as u32;

    let commands = DmaBuffer::allocate(COMMAND_QUEUE_BYTES / FRAME_SIZE).ok_or(Error::NoSpace)?;

    // The tables are the controller's choice of shape, not the kernel's: it
    // reports the entry size and the page size it wants, and both the base's
    // alignment and the size field are counted in those units.
    let device = find_table(base, GITS_TABLE_DEVICE).ok_or(Error::NotImplemented)?;
    let device_bytes = align_up(
        (1_usize << device_id_bits) * device.entry_size,
        device.page_size,
    );
    let device_table = DmaBuffer::allocate_aligned(frames_for(device_bytes), device.page_size)
        .ok_or(Error::NoSpace)?;

    let collection = find_table(base, GITS_TABLE_COLLECTION).ok_or(Error::NotImplemented)?;
    // One page is thousands of collections — far more CPUs than this kernel
    // can name — and the smallest table the controller will take.
    let collections =
        DmaBuffer::allocate_aligned(frames_for(collection.page_size), collection.page_size)
            .ok_or(Error::NoSpace)?;

    // The tables may only move while the ITS is disabled and quiescent; a
    // controller still reading a table it was pointed at is not one whose base
    // register can be rewritten.
    write_u32(base + GITS_CTLR, 0);
    if !wait_for_quiescent(base) {
        return Err(Error::DeviceError);
    }

    write_table_baser(base, device, GITS_TABLE_DEVICE, &device_table)?;
    write_table_baser(base, collection, GITS_TABLE_COLLECTION, &collections)?;

    let cbaser = commands.phys_addr() as u64
        | GITS_BASER_INNER_CACHEABLE
        | GITS_BASER_INNER_SHAREABLE
        | ((COMMAND_QUEUE_BYTES / FRAME_SIZE - 1) as u64)
        | GITS_CBASER_VALID;
    write_u64(base + GITS_CBASER, cbaser);
    // Writing the command queue base resets the read pointer to zero, so the
    // write pointer starts there too.
    write_u64(base + GITS_CWRITER, 0);

    let mut state = ItsState {
        base,
        commands,
        writer: 0,
        device_table,
        collections,
        translation_tables: Vec::new(),
        device_id_bits,
    };

    // The commands that follow are only executed once the ITS is enabled, and
    // the tables above may only move while it is not — so the enable is the
    // point between the two halves, not an afterthought.
    write_u32(base + GITS_CTLR, GITS_CTLR_ENABLE);
    dsb_sy();

    // One collection per CPU that has a redistributor, not just the boot CPU's:
    // a placement names a CPU by naming the collection that is the CPU's, and
    // a core that comes up after this point is already nameable when it does.
    for index in 0..gicv3::redistributor_count() {
        let Some(cpu) = gicv3::redistributor_cpu(index) else {
            continue;
        };
        let Some(rd_base) = gicv3::rd_base_for_cpu(cpu) else {
            continue;
        };
        state.map_collection(collection_for_cpu(cpu), rd_base)?;
    }

    // Nothing has claimed an MSI yet, and a machine whose devices stay quiet
    // would carry this path untested until one did — so the boot walks it
    // once itself, on the CPU running it.
    let boot_cpu = gicv3::current_cpu_id();
    let boot_rd = gicv3::rd_base_for_cpu(boot_cpu).ok_or(Error::DeviceError)?;
    let boot_target = collection_target(state.base, boot_rd);
    if !self_test(&mut state, boot_cpu, boot_target) {
        crate::println!("[its   ] self-test could not be set up");
    }

    Ok(state)
}

/// Walk the message path once, through the ITS, at boot.
///
/// The kernel registers an identity no device can own, maps it to a DeviceID
/// no device uses, and has the ITS translate an event for it — the same
/// translation and delivery a device's write gets.  The LPI that arrives is
/// taken by the trap later and answered by the handler here, so what the boot
/// proves is the whole chain: table, translation, LPI, trap, handler.  The
/// message is left pending on purpose: it is the trap's half that has to run.
fn self_test(state: &mut ItsState, cpu: u32, sync_target: u64) -> bool {
    let handler: IrqHandler = Arc::new(|identity| {
        crate::println!("[its   ] self-test delivered LPI {}", identity);
    });

    if irq_handlers::claim(gicv3::LPI_BASE, SELF_TEST_LPI, SELF_TEST_LPI, 1, handler).is_err() {
        return false;
    }
    if !gicv3::set_lpi_enabled(SELF_TEST_LPI, true) {
        return false;
    }
    if state
        .map_device(
            SELF_TEST_DEVICE_ID,
            SELF_TEST_LPI,
            1,
            &[collection_for_cpu(cpu)],
            &[sync_target],
        )
        .is_err()
    {
        return false;
    }

    state.submit(command_int(SELF_TEST_DEVICE_ID, 0)).is_ok() && state.sync(sync_target).is_ok()
}

/// What a `GITS_BASER<n>` reports about the table it can hold.
#[derive(Clone, Copy)]
struct BaserLayout {
    /// Which of the eight `GITS_BASER` registers this is.
    index: usize,
    /// Bytes per entry, which the controller chooses.
    entry_size: usize,
    /// Bytes per table page, which the controller chooses: the base address
    /// has to be aligned to it and the size field is counted in them.
    page_size: usize,
}

/// Bytes a `GITS_BASER<n>.PAGESIZE` field names.
fn page_size_bytes(field: u64) -> Option<usize> {
    match field {
        0 => Some(4096),
        1 => Some(16384),
        2 => Some(65536),
        _ => None,
    }
}

/// Find the `GITS_BASER<n>` that holds the table of `table_type`.
///
/// A register that reads as zero is a table type this controller does not
/// implement, which is how the specification says an absent table looks.
fn find_table(base: usize, table_type: u64) -> Option<BaserLayout> {
    for index in 0..GITS_BASER_COUNT {
        let value = read_u64(base + GITS_BASER + index * 8);
        if value == 0 || value == u64::MAX {
            continue;
        }
        if (value >> GITS_BASER_TYPE_SHIFT) & 0x7 != table_type {
            continue;
        }

        let entry_size = (((value >> GITS_BASER_ENTRY_SIZE_SHIFT) & 0x1f) + 1) as usize;
        let page_size = page_size_bytes((value >> GITS_BASER_PAGE_SIZE_SHIFT) & 0x3)?;
        return Some(BaserLayout {
            index,
            entry_size,
            page_size,
        });
    }
    None
}

/// Round `value` up to the next multiple of `alignment`.
fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

/// Point one `GITS_BASER<n>` at a table.
fn write_table_baser(
    base: usize,
    layout: BaserLayout,
    table_type: u64,
    table: &DmaBuffer,
) -> Result<(), Error> {
    let pages = table.len() / layout.page_size;
    if pages == 0 || pages > 512 {
        return Err(Error::InvalidArgument);
    }

    // The page size is an enumeration, not an exponent: 64 KiB is 0b10.
    let page_size_field = match layout.page_size {
        4096 => 0_u64,
        16384 => 1,
        65536 => 2,
        _ => return Err(Error::InvalidArgument),
    };
    let mut value = (table.phys_addr() as u64 & GITS_BASER_ADDRESS_MASK)
        | (table_type << GITS_BASER_TYPE_SHIFT)
        | ((layout.entry_size as u64 - 1) << GITS_BASER_ENTRY_SIZE_SHIFT)
        | ((pages - 1) as u64)
        | (page_size_field << GITS_BASER_PAGE_SIZE_SHIFT)
        | GITS_BASER_INNER_CACHEABLE
        | GITS_BASER_INNER_SHAREABLE
        | GITS_BASER_VALID;

    let address = base + GITS_BASER + layout.index * 8;
    write_u64(address, value);
    let read_back = read_u64(address);

    // A controller that does not implement the shareability this kernel asked
    // for cannot be given a cacheable table either: the architecture ties the
    // two together, and the retry is with the attributes it did accept.
    if read_back & GITS_BASER_SHAREABLE_MASK != value & GITS_BASER_SHAREABLE_MASK {
        value &= !(GITS_BASER_SHAREABLE_MASK | GITS_BASER_INNER_CACHEABLE_MASK);
        value |= GITS_BASER_INNER_NON_CACHEABLE;
        write_u64(address, value);
    }

    if read_u64(address) & GITS_BASER_VALID == 0 {
        return Err(Error::DeviceError);
    }
    Ok(())
}

/// Wait for the ITS to reach its quiescent state.
fn wait_for_quiescent(base: usize) -> bool {
    for _ in 0..1_000_000 {
        if read_u32(base + GITS_CTLR) & GITS_CTLR_QUIESCENT != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Bring the ITS up once, and answer whether it is up.
fn ensure_initialized() -> Result<usize, Error> {
    if let Some(state) = ITS_STATE.lock().as_ref() {
        return Ok(state.base);
    }
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        // Another caller is building it; there is nothing to wait on here
        // because the only caller is the boot's own single-threaded step.
        return Err(Error::Busy);
    }

    let base = its_base().ok_or(Error::NotImplemented)?;
    let state = build(base)?;
    crate::println!(
        "[its   ] GICv3 ITS at {:#x}: device table {:#x} for {} DeviceID(s), collections {:#x}, \
         one per CPU",
        base,
        state.device_table.phys_addr(),
        1_u32 << state.device_id_bits,
        state.collections.phys_addr()
    );
    *ITS_STATE.lock() = Some(state);
    Ok(base)
}

// -- MSI-X ----------------------------------------------------------------

const MSIX_ENTRY_BYTES: usize = 16;
/// The Vector Control mask bit: set, the entry cannot deliver.
const MSIX_VECTOR_MASK: u32 = 1;
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;

/// Where the kernel reaches a device's MSI-X table.
///
/// The table lives in a BAR, and this machine's BARs sit above the range the
/// runtime tables map, so it is reached through the same kind of alias the
/// driver's own BAR is (see [`crate::arch::platform`]); the address is fixed
/// and reserved, and a second window would collide with the first.
const MSIX_TABLE_VA: usize = 0x2_0080_0000;

/// An MSI-X table entry, as the device reads it.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct MsixTableEntry {
    address_low: u32,
    address_high: u32,
    data: u32,
    control: u32,
}

impl MsixTableEntry {
    /// The entry that delivers `event_id` through the ITS.
    ///
    /// The address is the ITS's translation register and nothing else: the
    /// device's DeviceID is an attribute of the write, taken from the
    /// requester id the interconnect carries, and a SoC that cannot carry one
    /// is a SoC with a window of its own in front of the ITS rather than a
    /// different address here.
    fn compose(translater: usize, event_id: u32) -> Self {
        let address = translater as u64;
        Self {
            address_low: address as u32,
            address_high: (address >> 32) as u32,
            data: event_id,
            control: 0,
        }
    }

    /// The entry that cannot deliver anything.
    ///
    /// A table entry takes effect as soon as it is written, so an entry this
    /// claim does not own is written with its mask bit set rather than left
    /// alone: whatever a previous user of the table left there, the device
    /// ends this write unable to raise it.
    fn masked() -> Self {
        Self {
            address_low: 0,
            address_high: 0,
            data: 0,
            control: MSIX_VECTOR_MASK,
        }
    }
}

/// A device's claim on the LPIs its MSI-X table will deliver.
///
/// The claim is taken at probe time, where the device is in hand, but the
/// table can only be programmed once the interrupt controller is up — so the
/// claim is what holds the two halves together.  [`Self::arm`] writes the
/// identities into the device's MSI-X table and lets the device signal;
/// [`Self::is_armed`] is how the owner tells the difference, so a completion
/// path waits on the device only once the device can say something.
#[derive(Clone)]
pub(crate) struct MsixClaim {
    inner: Arc<MsixClaimInner>,
}

struct MsixClaimInner {
    region: pci::EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    /// The DeviceID the ITS will translate this function's messages under.
    device_id: u32,
    first_lpi: u32,
    /// The entries the function's table has, which is how wide the table is
    /// whenever it is written.
    count: u32,
    /// The table entries this claim owns, in LPI order: `entries[i]` is
    /// delivered on `first_lpi + i`.  Every other entry of the table is
    /// written masked, so the device cannot deliver an LPI this claim did not
    /// take.
    entries: Vec<u16>,
    armed: AtomicBool,
}

impl MsixClaim {
    /// The first interrupt identity this device's table delivers.
    pub(crate) fn first_irq(&self) -> u32 {
        self.inner.first_lpi
    }

    /// Whether the table has been programmed and the device let through.
    pub(crate) fn is_armed(&self) -> bool {
        self.inner.armed.load(Ordering::Acquire)
    }

    /// Map this device in the ITS, program its MSI-X table, and let it signal.
    ///
    /// Every step is ordered so that the device cannot raise an interrupt
    /// before there is something to receive it: the translation is mapped and
    /// the LPI is enabled in the configuration table first, then the table
    /// entries are written and read back, and only then is the function
    /// unmasked.
    pub(crate) fn arm(&self) -> Result<(), Error> {
        let inner = &self.inner;
        let (translater, placed) = {
            let mut state = ITS_STATE.lock();
            let state = state.as_mut().ok_or(Error::NotImplemented)?;

            // Where each identity this claim took is delivered.  Identities
            // are placed in turn over the CPUs that can receive, so a device
            // with several queues has them completed by different cores
            // instead of all by the boot CPU.
            let count = inner.entries.len();
            let mut collections = Vec::with_capacity(count);
            let mut placed = Vec::with_capacity(count);
            let mut sync_targets: Vec<u64> = Vec::new();
            for index in 0..count as u32 {
                let cpu = gicv3::lpi_cpu_for_entry(index).ok_or(Error::DeviceError)?;
                let rd_base = gicv3::rd_base_for_cpu(cpu).ok_or(Error::DeviceError)?;
                collections.push(collection_for_cpu(cpu));
                placed.push(cpu);
                let target = collection_target(state.base, rd_base);
                if !sync_targets.contains(&target) {
                    sync_targets.push(target);
                }
            }

            state.map_device(
                inner.device_id,
                inner.first_lpi,
                count as u32,
                &collections,
                &sync_targets,
            )?;
            (state.base + GITS_TRANSLATER, placed)
        };

        for index in 0..inner.entries.len() as u32 {
            if !gicv3::set_lpi_enabled(inner.first_lpi + index, true) {
                return Err(Error::DeviceError);
            }
        }

        program_msix_table(inner, translater)?;
        inner.armed.store(true, Ordering::Release);
        crate::println!(
            "[its   ] MSI-X {:02x}:{:02x}.{}: irq {}-{} on table entries {:?} placed on cpu {:?}",
            inner.bus,
            inner.device,
            inner.function,
            inner.first_lpi,
            inner.first_lpi + inner.entries.len() as u32 - 1,
            inner.entries,
            placed
        );
        Ok(())
    }
}

/// The MSI-X capability of a function, and where it was found.
fn msix_capability(
    region: &pci::EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
) -> Option<pci::MsixCapability> {
    let offset = pci::pci_capability_find(region, bus, device, function, pci::cap_id::MSI_X)?;
    // SAFETY: `offset` is the location of the MSI-X capability the walk just
    // found on this function.
    let capability = unsafe { pci::pci_capability_msix(region, bus, device, function, offset) };
    Some(capability)
}

/// Whether the function's MSI-X is already enabled.
fn msix_enabled(region: &pci::EcamRegion, bus: u8, device: u8, function: u8) -> bool {
    msix_capability(region, bus, device, function)
        .map(|capability| capability.message_control & MSIX_ENABLE != 0)
        .unwrap_or(false)
}

/// How many entries the function's MSI-X table has.
fn msix_entry_count(region: &pci::EcamRegion, bus: u8, device: u8, function: u8) -> Option<u32> {
    msix_capability(region, bus, device, function)
        .map(|capability| ((capability.message_control & 0x07ff) as u32) + 1)
}

/// The DeviceID the ITS knows a PCIe function by.
///
/// It is the requester ID the function's messages carry: the bus, the device
/// and the function, packed the way configuration space addresses them.
fn device_id_of(bus: u8, device: u8, function: u8) -> u32 {
    ((bus as u32) << 8) | ((device as u32) << 3) | function as u32
}

/// Claim the LPIs this device's MSI-X table will deliver for `handler`.
///
/// Answers [`Error::NotImplemented`] on a machine with no ITS — the function
/// is left for whoever programs its table, and its owner stays on the polling
/// path — and [`Error::AlreadyExists`] when the function's MSI-X is already
/// enabled, which means somebody else owns it.
pub(crate) fn claim_msix(
    region: &pci::EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    named: &[(u16, IrqHandler)],
) -> Result<MsixClaim, Error> {
    if its_base().is_none() {
        return Err(Error::NotImplemented);
    }
    if msix_enabled(region, bus, device, function) {
        return Err(Error::AlreadyExists);
    }

    let count = msix_entry_count(region, bus, device, function).ok_or(Error::NotImplemented)?;
    if count == 0 || count > EVENT_COUNT {
        return Err(Error::InvalidArgument);
    }

    // One identity per entry the driver names, and none for the rest: a table
    // entry this claim does not own is written masked, which is what keeps the
    // claim the driver's requirement rather than the table's size.
    let handlers =
        crate::arch::platform::msix_named_handlers(count, named).ok_or(Error::InvalidArgument)?;
    let first_lpi = irq_handlers::claim_each(
        gicv3::LPI_BASE,
        FIRST_DEVICE_LPI,
        LAST_DEVICE_LPI,
        &handlers,
    )?;
    // Table entry `entries[i]` is delivered on LPI `first_lpi + i`.
    let entries: Vec<u16> = named.iter().map(|(entry, _)| *entry).collect();

    Ok(MsixClaim {
        inner: Arc::new(MsixClaimInner {
            region: *region,
            bus,
            device,
            function,
            device_id: device_id_of(bus, device, function),
            first_lpi,
            count,
            entries,
            armed: AtomicBool::new(false),
        }),
    })
}

/// Write the claimed identities into the device's MSI-X table and let it go.
fn program_msix_table(inner: &MsixClaimInner, translater: usize) -> Result<(), Error> {
    let (bus, device, function) = (inner.bus, inner.device, inner.function);
    let region = &inner.region;

    let capability = msix_capability(region, bus, device, function).ok_or(Error::NotImplemented)?;
    let capability_offset = capability.offset as u16;
    let table_bir = (capability.table_bir_and_offset & 0x07) as u16;
    let table_offset = (capability.table_bir_and_offset & 0xffff_fff8) as u64;

    let bar = pci::pci_read_bar_64(
        region,
        bus,
        device,
        function,
        pci::reg::BAR0 + table_bir * 4,
    );
    if bar == 0 {
        return Err(Error::InvalidArgument);
    }
    let table_phys = bar
        .checked_add(table_offset)
        .ok_or(Error::InvalidArgument)?;

    let table_bytes = inner.count as usize * MSIX_ENTRY_BYTES;
    // SAFETY: the MSI-X table is a live MMIO range of this device's BAR, and
    // `MSIX_TABLE_VA` is this platform's reserved address for reaching one.
    let table = unsafe { super::mmu::map_device_mmio_at(MSIX_TABLE_VA, table_phys, table_bytes) }
        .ok_or(Error::DeviceError)?;

    // Every entry of the table is written, and each comes out of this step
    // masked or unowned: the owned ones name an event id (which is where the
    // ITS maps them) and the rest are the mask and nothing else.
    for index in 0..inner.count {
        let entry = match inner.entries.iter().position(|e| *e as u32 == index) {
            Some(offset) => MsixTableEntry::compose(translater, offset as u32),
            None => MsixTableEntry::masked(),
        };
        let address = table as usize + index as usize * MSIX_ENTRY_BYTES;
        // The table wants four 32-bit stores, which is also the only alignment
        // the entries are guaranteed: an entry is 16 bytes but its address is
        // only 4-byte aligned inside the BAR.
        write_u32(address, entry.address_low);
        write_u32(address + 4, entry.address_high);
        write_u32(address + 8, entry.data);
        write_u32(address + 12, entry.control);
    }
    dsb_sy();

    // Read it back.  QEMU's devices decode their BAR, so the words that went
    // in are the words that come out; a table nobody wrote would read as
    // zeroes, and this is where that shows instead of as a missing interrupt
    // later.
    for index in 0..inner.count {
        let address = table as usize + index as usize * MSIX_ENTRY_BYTES;
        let read_back = MsixTableEntry {
            address_low: read_u32(address),
            address_high: read_u32(address + 4),
            data: read_u32(address + 8),
            control: read_u32(address + 12),
        };
        let expected = match inner.entries.iter().position(|e| *e as u32 == index) {
            Some(offset) => MsixTableEntry::compose(translater, offset as u32),
            None => MsixTableEntry::masked(),
        };
        if read_back != expected {
            return Err(Error::DeviceError);
        }
    }

    // Enable MSI-X and clear the function mask, the two bits that stand
    // between a programmed table and a device that may signal.
    let control = (capability.message_control | MSIX_ENABLE) & !MSIX_FUNCTION_MASK;
    // SAFETY: the message-control half of the MSI-X capability found above,
    // inside this function's configuration space.
    unsafe {
        region.write_u16(bus, device, function, capability_offset + 2, control);
    }

    Ok(())
}

// -- Deferred arming ------------------------------------------------------

/// Claims waiting for the controller that will carry them.
///
/// A driver claims its device's identities at probe time, which is *before*
/// [`program_device_msix`] runs; this is where the claim waits in between.
static PENDING: SpinLock<Vec<MsixClaim>> = SpinLock::new(Vec::new());

/// Hold a claim until the ITS can be programmed with it.
pub(crate) fn defer_msix_arming(claim: MsixClaim) {
    PENDING.lock().push(claim);
}

/// Program every device's MSI-X table, now that the controller is up.
///
/// Answers how many devices were armed.  A device whose programming fails is
/// not armed and says so; its owner's completion path sees
/// [`MsixClaim::is_armed`] answer `false` and polls, which is the same path it
/// would have taken on a machine with no ITS at all.
pub(crate) fn program_device_msix() -> usize {
    let claims: Vec<MsixClaim> = PENDING.lock().drain(..).collect();
    if claims.is_empty() {
        return 0;
    }

    if let Err(error) = ensure_initialized() {
        crate::println!(
            "[its   ] no ITS on this machine ({:?}); device MSI-X stays unprogrammed",
            error
        );
        return 0;
    }

    let mut armed = 0;
    for claim in &claims {
        let (bus, device, function) = (claim.inner.bus, claim.inner.device, claim.inner.function);
        match claim.arm() {
            Ok(()) => {
                armed += 1;
                crate::println!(
                    "[its   ] MSI-X on {:02x}:{:02x}.{} delivers LPI {}..{} on table entries \
                     {:?} (DeviceID {})",
                    bus,
                    device,
                    function,
                    claim.first_irq(),
                    claim.first_irq() + claim.inner.entries.len() as u32 - 1,
                    claim.inner.entries,
                    claim.inner.device_id
                );
            }
            Err(error) => {
                crate::println!(
                    "[its   ] MSI-X on {:02x}:{:02x}.{} not programmed: {:?}",
                    bus,
                    device,
                    function,
                    error
                );
            }
        }
    }

    armed
}

/// Run the handler an LPI was claimed for.
///
/// The trap path calls this with the identity it acknowledged; answers whether
/// a handler ran, which is how an LPI nobody owns is counted as spurious
/// rather than dropped.
pub(crate) fn dispatch_lpi(identity: u32) -> bool {
    irq_handlers::dispatch(gicv3::LPI_BASE, identity)
}

/// Whether an acknowledged identity is in the architecture's LPI range.
///
/// The range starts at 8192 and runs to the top of the interrupt-id space; an
/// identity below it is a wire-driven interrupt with its own disposition.
pub(crate) fn is_lpi(identity: u32) -> bool {
    identity >= gicv3::LPI_BASE
}
