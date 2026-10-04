//! src/arch/aarch64/mod.rs
//!
//! AArch64 architecture bring-up glue, platform hooks, and backend exports.

// Most of this module is bare-metal bring-up; a host build compiles it but
// never calls it.
#![cfg_attr(not(target_os = "none"), allow(dead_code))]

use core::arch::asm;
use core::fmt::Write;
use core::fmt::{self};
use core::ptr::read_volatile;
use core::ptr::write_volatile;

use crate::arch::Arch;
use crate::kernel::sync::SpinLock;

#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("trap.S"));

pub struct AArch64;

impl Arch for AArch64 {
    fn init_early() {
        enable_fp_simd();
        trap::init();
        serial::init();
    }

    fn halt() {
        // SAFETY: `wfi` parks this core until an interrupt and touches no
        // memory; EL1 may execute it unconditionally.
        unsafe {
            asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }

    fn reboot() -> ! {
        crate::arch::aarch64::psci::system_reset()
    }
}

const CPACR_EL1_FPEN_EL0_EL1: u64 = 0b11 << 20;

fn enable_fp_simd() {
    let mut cpacr_el1: u64;

    // SAFETY: CPACR_EL1 is an EL1 system register and the FP/SIMD trap bits it
    // holds are the kernel's to set during bring-up; no memory operand is
    // involved.
    unsafe {
        // User payloads and compiler-generated code may rely on FP/SIMD state, so
        // enable access early during EL1 bring-up instead of faulting lazily.
        asm!(
            "mrs {cpacr_el1}, CPACR_EL1",
            cpacr_el1 = out(reg) cpacr_el1,
            options(nomem, nostack, preserves_flags)
        );
        cpacr_el1 |= CPACR_EL1_FPEN_EL0_EL1;
        asm!(
            "msr CPACR_EL1, {cpacr_el1}",
            "isb",
            cpacr_el1 = in(reg) cpacr_el1,
            options(nostack, preserves_flags)
        );
    }
}

pub mod interrupts {
    use core::arch::asm;

    pub fn are_enabled() -> bool {
        let daif: u64;

        // SAFETY: reading DAIF is an EL1 system-register read with no memory
        // side effects; the mask bits are what this asks about.
        unsafe {
            asm!("mrs {daif}, DAIF", daif = out(reg) daif, options(nomem, nostack, preserves_flags));
        }

        daif & (1 << 7) == 0
    }

    pub fn enable() {
        // SAFETY: clearing the DAIF masks is an EL1 operation; it has no memory
        // operand, and the caller is responsible for being in a state where
        // taking an interrupt is correct.
        unsafe {
            asm!(
                "msr DAIFClr, #0xf",
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    pub fn disable() {
        // SAFETY: as `enable` — setting the DAIF masks, which the caller pairs
        // with a later enable.
        unsafe {
            asm!(
                "msr DAIFSet, #0xf",
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

pub mod context;
pub mod cpufreq;
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;
pub mod devices;
pub(crate) mod exception;
pub(crate) mod gicv3;
pub mod irq_balance;
pub(crate) mod its;
pub(crate) mod mmio;
pub mod mmu;
pub mod pci;
pub mod percpu;
pub mod psci;
pub mod rand;
pub mod rtc;
pub mod signal;
pub mod trap;
pub mod user_access;

pub(crate) mod smp;
pub mod tlb;

pub mod interrupt_controller {
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicU8;
    use core::sync::atomic::Ordering;

    use super::gicv3;
    use super::read_volatile;
    use super::write_volatile;
    use crate::arch::interrupt_controller::InterruptController;

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    /// The controller revision this machine reports, once anything has asked.
    ///
    /// Zero is "not read yet"; 2 and 3 are the values the rest of the module
    /// branches on.  The answer cannot change while the kernel runs, and the
    /// question sits on the interrupt path, so it is read from the hardware
    /// once and cached.
    static VERSION: AtomicU8 = AtomicU8::new(0);

    const GICD_BASE_DEFAULT: usize = 0x0800_0000;
    const GICC_BASE_DEFAULT: usize = 0x0801_0000;
    const GICR_BASE_DEFAULT: usize = 0x080A_0000;

    /// Cores a GICv2 distributor can address.
    ///
    /// Its SGI target list is eight bits wide, so a ninth core could be
    /// started and then never woken.  GICv3 does not have the limit: its
    /// redistributors are per-PE and an SGI names an affinity.
    pub(crate) const GICV2_CPU_INTERFACES: u32 = 8;

    pub(crate) fn gicd_base() -> usize {
        crate::arch::fdt::platform_info()
            .gicd_base
            .unwrap_or(GICD_BASE_DEFAULT)
    }

    fn gicc_base() -> usize {
        crate::arch::fdt::platform_info()
            .gicc_base
            .unwrap_or(GICC_BASE_DEFAULT)
    }

    /// The first redistributor frame, on a machine that has them.
    pub(crate) fn gicr_base() -> usize {
        crate::arch::fdt::platform_info()
            .gicr_base
            .unwrap_or(GICR_BASE_DEFAULT)
    }

    const GICD_CTLR: usize = 0x000;
    pub(crate) const GICD_TYPER: usize = 0x004;
    const GICD_IGROUPR0: usize = 0x080;
    const GICD_ISENABLER0: usize = 0x100;
    const GICD_ICPENDR0: usize = 0x280;
    const GICD_IPRIORITYR: usize = 0x400;
    const GICD_ITARGETSR: usize = 0x1800;
    const GICD_SGIR: usize = 0xF00;

    /// Peripheral ID 2 at the two addresses the two revisions put it at.
    ///
    /// Bits [7:4] report the architecture revision — 2 for GICv2, 3 for
    /// GICv3, 4 for a GICv4 that keeps the v3 programming model.  A GICv2
    /// distributor is a 4 KiB block and keeps its identification registers at
    /// the end of it; GICv3 grew the block to 64 KiB and moved them to the top
    /// of the new window, so a probe has to ask at the address the revision it
    /// is looking for actually implements.
    const GICD_PIDR2_V2: usize = 0x0FE8;
    const GICD_PIDR2_V3: usize = 0xFFE8;

    const GICC_CTLR: usize = 0x0000;
    const GICC_PMR: usize = 0x0004;
    const GICC_BPR: usize = 0x0008;
    const GICC_IAR: usize = 0x000C;
    const GICC_EOIR: usize = 0x0010;

    const GIC_ENABLE_GROUP0: u32 = 1 << 0;
    const GIC_ENABLE_GROUP1: u32 = 1 << 1;
    const SPURIOUS_INTERRUPT_ID_START: u32 = 1020;

    fn distributor_register(offset: usize) -> *mut u32 {
        (gicd_base() + offset) as *mut u32
    }

    fn cpu_interface_register(offset: usize) -> *mut u32 {
        (gicc_base() + offset) as *mut u32
    }

    fn distributor_read(offset: usize) -> u32 {
        // SAFETY: the GIC distributor is device MMIO inside the low window the
        // runtime tables map as device memory, and `offset` names one of its
        // registers.
        unsafe { read_volatile(distributor_register(offset)) }
    }

    fn distributor_write(offset: usize, value: u32) {
        // SAFETY: as `distributor_read` — the same register block, on the write
        // side.
        unsafe {
            write_volatile(distributor_register(offset), value);
        }
    }

    fn cpu_interface_read(offset: usize) -> u32 {
        // SAFETY: the CPU interface is device MMIO in the same mapped window,
        // and `offset` names one of its registers.
        unsafe { read_volatile(cpu_interface_register(offset)) }
    }

    fn cpu_interface_write(offset: usize, value: u32) {
        // SAFETY: as `cpu_interface_read` — the same block, on the write side.
        unsafe {
            write_volatile(cpu_interface_register(offset), value);
        }
    }

    fn priority_register(interrupt_id: u32) -> *mut u8 {
        (gicd_base() + GICD_IPRIORITYR + interrupt_id as usize) as *mut u8
    }

    /// Ask the distributor which controller revision it is.
    ///
    /// The v2 address is probed first because a GICv2 only answers there, and
    /// a GICv3 answers zero there — the offset is inside its window but is not
    /// a register it implements.  The device tree's `arm,gic-v3` node is the
    /// tiebreak for a machine whose identification registers read back as
    /// nothing: it named its controller, and that name is a better answer than
    /// refusing to boot the machine it described.
    fn detect_version() -> Option<u8> {
        let v2_revision = (distributor_read(GICD_PIDR2_V2) >> 4) & 0xF;
        if v2_revision == 2 {
            return Some(2);
        }

        let v3_revision = (distributor_read(GICD_PIDR2_V3) >> 4) & 0xF;
        if v3_revision == 3 || v3_revision == 4 {
            return Some(3);
        }

        if crate::arch::fdt::platform_info().gicv3_detected {
            return Some(3);
        }

        None
    }

    fn version() -> Option<u8> {
        let cached = VERSION.load(Ordering::Acquire);
        if cached != 0 {
            return Some(cached);
        }

        let detected = detect_version()?;
        VERSION.store(detected, Ordering::Release);
        Some(detected)
    }

    /// Whether the machine in front of the kernel is a GICv3 one.
    ///
    /// Asked by the CPU-discovery path, whose answer differs between the two
    /// revisions: a GICv2 distributor caps how many cores can be woken, while
    /// a GICv3 controller is asked how many redistributors it enumerated.
    pub(crate) fn is_v3() -> bool {
        version() == Some(3)
    }

    /// PEs a GICv3 controller has a redistributor frame for.
    pub(crate) fn redistributor_count() -> u32 {
        gicv3::redistributor_count() as u32
    }

    /// Singleton GICv2 controller used by the arch-level dispatch.
    pub static GICV2_CONTROLLER: GicV2Controller = GicV2Controller;

    /// ARM Generic Interrupt Controller v2 (GIC-400 compatible).
    pub struct GicV2Controller;

    impl InterruptController for GicV2Controller {
        fn init(&self) {
            if INITIALIZED.swap(true, Ordering::Acquire) {
                return;
            }

            // Only reached when the distributor reported revision 2: the
            // dispatch layer read that before choosing this controller, and a
            // machine it does not recognise stops there rather than being
            // programmed with the v2 layout.
            //
            // Reprogram the distributor and CPU interface atomically with local IRQs
            // masked.
            super::interrupts::disable();

            distributor_write(GICD_CTLR, 0);
            cpu_interface_write(GICC_CTLR, 0);
            cpu_interface_write(GICC_PMR, 0xFF);
            cpu_interface_write(GICC_BPR, 0);

            distributor_write(GICD_IGROUPR0, u32::MAX);
            distributor_write(GICD_ICPENDR0, u32::MAX);
            for interrupt_id in 0..32 {
                GICV2_CONTROLLER.set_priority(interrupt_id, 0x80);
            }

            distributor_write(GICD_CTLR, GIC_ENABLE_GROUP0 | GIC_ENABLE_GROUP1);
            cpu_interface_write(GICC_CTLR, GIC_ENABLE_GROUP0 | GIC_ENABLE_GROUP1);
        }

        fn end_of_interrupt(&self, acknowledge: u32) {
            if interrupt_id(acknowledge) >= SPURIOUS_INTERRUPT_ID_START {
                return;
            }
            cpu_interface_write(GICC_EOIR, acknowledge);
        }

        fn enable_interrupt(&self, interrupt_id: u32) {
            let register = GICD_ISENABLER0 + ((interrupt_id as usize / 32) * 4);
            let bit = 1_u32 << (interrupt_id % 32);
            distributor_write(register, bit);
        }

        fn set_priority(&self, interrupt_id: u32, priority: u8) {
            // SAFETY: a byte of the distributor's priority array — the register
            // the GIC architecture puts at this offset, in the mapped window.
            unsafe {
                write_volatile(priority_register(interrupt_id), priority);
            }
        }
    }

    // -- GIC-specific helpers that are not part of the generic trait ---------

    /// Return the active interrupt controller singleton for this platform.
    ///
    /// Which one it is follows from what the distributor reports, and that is
    /// read on the first call — which is bring-up, before any interrupt can
    /// arrive.  A revision this kernel has no driver for stops here, with the
    /// reason printed, rather than being programmed with a layout that means
    /// something else.
    pub(crate) fn active_controller() -> &'static dyn InterruptController {
        match version() {
            Some(3) => &gicv3::GICV3_CONTROLLER,
            Some(2) => &GICV2_CONTROLLER,
            _ => {
                crate::println!(
                    "[irq   ] this kernel's aarch64 interrupt driver implements GICv2 and \
                     GICv3; the controller at {:#x} reports neither — stopping instead of \
                     programming registers that mean something else",
                    gicd_base()
                );
                loop {
                    crate::arch::halt();
                }
            }
        }
    }

    /// Per-CPU interrupt-controller initialisation (called on each AP).
    ///
    /// Answers whether this core can be interrupted at all.  On a GICv3 that
    /// is a real question — its redistributor is per-CPU state that has to be
    /// found and woken, and the core asking is the only one that can do it.
    pub(crate) fn init_gicc() -> bool {
        match version() {
            Some(3) => gicv3::init_cpu(),
            _ => {
                cpu_interface_write(GICC_PMR, 0xFF);
                cpu_interface_write(GICC_BPR, 0);
                cpu_interface_write(GICC_CTLR, GIC_ENABLE_GROUP0 | GIC_ENABLE_GROUP1);
                true
            }
        }
    }

    /// Put one interrupt into Group 1, the group this kernel drives.
    pub(crate) fn set_group1(interrupt_id: u32) {
        if version() == Some(3) {
            gicv3::set_group1(interrupt_id);
            return;
        }

        let register = GICD_IGROUPR0 + ((interrupt_id as usize / 32) * 4);
        let bit = 1_u32 << (interrupt_id % 32);
        let value = distributor_read(register) | bit;
        distributor_write(register, value);
    }

    /// Re-target an SPI (interrupt id >= 32) to a specific CPU.
    ///
    /// The two revisions route in opposite ways: GICv2 writes a CPU bitmask
    /// into the per-interrupt ITARGETSR byte (GICD base + 0x1800 + id), while
    /// GICv3 writes the target PE's affinity into a 64-bit `GICD_IROUTER`.
    /// SGIs and PPIs (ids < 32) are per-CPU by design and cannot be
    /// re-targeted; the caller (irq_balance) checks routability before
    /// invoking this.
    pub(crate) fn set_irq_affinity(interrupt_id: u32, cpu_id: u32) {
        if interrupt_id < 32 {
            return;
        }

        if version() == Some(3) {
            gicv3::set_affinity(interrupt_id, cpu_id);
            return;
        }

        let mask = 1_u8 << (cpu_id % 8);
        let register = (gicd_base() + GICD_ITARGETSR + interrupt_id as usize) as *mut u8;
        // SAFETY: the per-interrupt target byte of the distributor's own
        // register block, in the low window the tables map as device memory.
        unsafe {
            write_volatile(register, mask);
        }
    }

    pub(crate) fn claim_interrupt() -> Option<u32> {
        if version() == Some(3) {
            return gicv3::claim();
        }

        let acknowledge = cpu_interface_read(GICC_IAR);
        (interrupt_id(acknowledge) < SPURIOUS_INTERRUPT_ID_START).then_some(acknowledge)
    }

    pub(crate) fn interrupt_id(acknowledge: u32) -> u32 {
        if version() == Some(3) {
            return gicv3::interrupt_id(acknowledge);
        }

        acknowledge & 0x03ff
    }

    /// Write end-of-interrupt for an acknowledged interrupt.
    pub(crate) fn acknowledge(acknowledge: u32) {
        if version() == Some(3) {
            gicv3::end_of_interrupt(acknowledge);
            return;
        }

        GICV2_CONTROLLER.end_of_interrupt(acknowledge);
    }

    /// Send one SGI to the CPU the kernel calls `cpu_id`.
    pub(crate) fn send_sgi_to_cpu(interrupt_id: u8, cpu_id: u32) {
        if version() == Some(3) {
            gicv3::send_sgi(interrupt_id, cpu_id);
            return;
        }

        // A GICv2 distributor names its targets as bits in an eight-bit
        // list, so a CPU the list cannot name is not one this can reach.
        if interrupt_id >= 16 || cpu_id >= GICV2_CPU_INTERFACES {
            return;
        }
        let register = (gicd_base() + GICD_SGIR) as *mut u32;
        // SAFETY: the distributor's software-generated-interrupt register, in
        // the mapped device window; the checks above keep the id in range and
        // the target inside the list.
        unsafe {
            write_volatile(register, ((1_u32 << cpu_id) << 16) | interrupt_id as u32);
        }
    }

    /// Send one SGI to every other CPU.
    pub(crate) fn send_sgi_all_except_self(interrupt_id: u8) {
        if version() == Some(3) {
            gicv3::send_sgi_all_except_self(interrupt_id);
            return;
        }

        if interrupt_id >= 16 {
            return;
        }
        let register = (gicd_base() + GICD_SGIR) as *mut u32;
        // SAFETY: as `send_sgi_to_cpu` — the same register, with the "all
        // except self" target filter the broadcast wants.
        unsafe {
            write_volatile(register, (1_u32 << 24) | interrupt_id as u32);
        }
    }
}

pub mod serial {
    use super::fmt;
    use super::read_volatile;
    use super::write_volatile;
    use super::SpinLock;
    use super::Write;

    const PL011_UART_BASE: usize = 0x0900_0000;

    fn pl011_uart_base() -> usize {
        crate::arch::fdt::platform_info()
            .uart_base
            .unwrap_or(PL011_UART_BASE)
    }
    const DR_OFFSET: usize = 0x000;
    const FR_OFFSET: usize = 0x018;
    const IBRD_OFFSET: usize = 0x024;
    const FBRD_OFFSET: usize = 0x028;
    const LCRH_OFFSET: usize = 0x02C;
    const CR_OFFSET: usize = 0x030;
    const IMSC_OFFSET: usize = 0x038;
    const ICR_OFFSET: usize = 0x044;

    const FR_TXFF: u32 = 1 << 5;
    const FR_RXFE: u32 = 1 << 4;
    const CR_UARTEN: u32 = 1 << 0;
    const CR_TXE: u32 = 1 << 8;
    const CR_RXE: u32 = 1 << 9;
    const LCRH_FEN: u32 = 1 << 4;
    const LCRH_WLEN_8BIT: u32 = 0b11 << 5;

    struct Pl011Uart {
        base: usize,
        initialized: bool,
    }

    impl Pl011Uart {
        const fn new(base: usize) -> Self {
            Self {
                base,
                initialized: false,
            }
        }

        fn register(&self, offset: usize) -> *mut u32 {
            (self.base + offset) as *mut u32
        }

        fn read(&self, offset: usize) -> u32 {
            // SAFETY: the redistributor's own register block, whose base the
            // platform described, inside the mapped device window.
            unsafe { read_volatile(self.register(offset)) }
        }

        fn write(&self, offset: usize, value: u32) {
            // SAFETY: as `read` — the same block, on the write side.
            unsafe {
                write_volatile(self.register(offset), value);
            }
        }

        fn init(&mut self) {
            // These divisors target the QEMU `virt` PL011 default clock with a
            // conventional 115200 8N1 configuration.
            self.write(CR_OFFSET, 0);
            self.write(IMSC_OFFSET, 0);
            self.write(ICR_OFFSET, 0x07ff);
            self.write(IBRD_OFFSET, 13);
            self.write(FBRD_OFFSET, 2);
            self.write(LCRH_OFFSET, LCRH_FEN | LCRH_WLEN_8BIT);
            self.write(CR_OFFSET, CR_UARTEN | CR_TXE | CR_RXE);
            self.initialized = true;
        }

        fn write_byte(&mut self, byte: u8) {
            if !self.initialized {
                self.init();
            }

            while self.read(FR_OFFSET) & FR_TXFF != 0 {}

            self.write(DR_OFFSET, byte as u32);
        }

        fn try_read_byte(&mut self) -> Option<u8> {
            if !self.initialized {
                self.init();
            }

            if self.read(FR_OFFSET) & FR_RXFE != 0 {
                return None;
            }

            Some(self.read(DR_OFFSET) as u8)
        }
    }

    impl Write for Pl011Uart {
        fn write_str(&mut self, message: &str) -> fmt::Result {
            for byte in message.bytes() {
                if byte == b'\n' {
                    self.write_byte(b'\r');
                }

                self.write_byte(byte);
            }

            Ok(())
        }
    }

    static SERIAL0: SpinLock<Pl011Uart> = SpinLock::new(Pl011Uart::new(PL011_UART_BASE));

    pub fn init() {
        let mut uart = SERIAL0.lock();
        uart.base = pl011_uart_base();
        uart.init();
    }

    pub fn write_str(message: &str) {
        let _ = SERIAL0.lock().write_str(message);
    }

    pub fn write_byte(byte: u8) {
        SERIAL0.lock().write_byte(byte);
    }

    pub fn try_read_byte() -> Option<u8> {
        SERIAL0.lock().try_read_byte()
    }

    pub fn write_fmt(args: fmt::Arguments<'_>) -> fmt::Result {
        let mut serial = SERIAL0.lock();
        serial.write_fmt(args)
    }
}

pub mod timer {
    use core::arch::asm;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;

    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

    pub const TIMER_INTERRUPT_ID: u32 = 30;
    const TIMER_TICK_HZ: u32 = 100;
    const CNTP_CTL_ENABLE: u64 = 1 << 0;

    pub fn init() {
        if INITIALIZED.swap(true, Ordering::Acquire) {
            return;
        }

        let counter_frequency = crate::arch::fdt::platform_info()
            .timer_frequency
            .unwrap_or_else(read_counter_frequency);
        // Keep the generic timer cadence aligned with the scheduler's 100 Hz tick.
        let interval = (counter_frequency / TIMER_TICK_HZ as u64).max(1);
        TIMER_INTERVAL.store(interval, Ordering::Relaxed);

        super::interrupt_controller::set_group1(TIMER_INTERRUPT_ID);
        crate::arch::interrupt_controller::set_priority(TIMER_INTERRUPT_ID, 0x40);
        crate::arch::interrupt_controller::enable_interrupt(TIMER_INTERRUPT_ID);
        program_next_tick(interval);
    }

    pub fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
    }

    /// Per-CPU timer initialisation (called on each AP).
    pub(crate) fn init_ap() {
        let counter_frequency = crate::arch::fdt::platform_info()
            .timer_frequency
            .unwrap_or_else(read_counter_frequency);
        let interval = (counter_frequency / TIMER_TICK_HZ as u64).max(1);
        TIMER_INTERVAL.store(interval, Ordering::Relaxed);

        // The timer is a private peripheral interrupt, and so is every register
        // that configures it: in GICv2 the SGI/PPI bank of the distributor
        // (`IGROUPR0`, `IPRIORITYR0-7`, `ISENABLER0`) is banked, so `init`
        // configured the BSP's copy and not this one.  A core that arms its
        // countdown without enabling its own PPI counts down to an interrupt
        // nobody will take: it then idles for a tick that never arrives, and so
        // does every thread parked on it — a sleeper never wakes, and a
        // long-running thread is never preempted.
        super::interrupt_controller::set_group1(TIMER_INTERRUPT_ID);
        crate::arch::interrupt_controller::set_priority(TIMER_INTERRUPT_ID, 0x40);
        crate::arch::interrupt_controller::enable_interrupt(TIMER_INTERRUPT_ID);

        program_next_tick(interval);
    }

    pub(crate) fn prepare_pending_interrupt() -> Option<u64> {
        timer_interrupt_pending().then(prepare_next_tick)
    }

    pub(crate) fn prepare_interrupt(interrupt_id: u32) -> Option<u64> {
        if interrupt_id != TIMER_INTERRUPT_ID {
            return None;
        }

        Some(prepare_next_tick())
    }

    fn read_counter_frequency() -> u64 {
        let counter_frequency: u64;

        // SAFETY: CNTFRQ_EL0 is a read-only EL0-visible counter register that
        // EL1 may read; the instruction touches no memory.
        unsafe {
            asm!(
                "mrs {counter_frequency}, CNTFRQ_EL0",
                counter_frequency = out(reg) counter_frequency,
                options(nomem, nostack, preserves_flags)
            );
        }

        counter_frequency
    }

    fn timer_interrupt_pending() -> bool {
        let control: u64;

        // SAFETY: as above — CNTP_CTL_EL0 read, one of the timer's own control
        // registers.
        unsafe {
            asm!(
                "mrs {control}, CNTP_CTL_EL0",
                control = out(reg) control,
                options(nomem, nostack, preserves_flags)
            );
        }

        control & (1 << 2) != 0
    }

    fn prepare_next_tick() -> u64 {
        let next_ticks = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
        let interval = TIMER_INTERVAL.load(Ordering::Relaxed).max(1);
        program_next_tick(interval);
        next_ticks
    }

    fn program_next_tick(interval: u64) {
        // SAFETY: the two timer registers this core owns — the interval reload
        // and the control word — written from EL1; the `isb` orders the write
        // before the next instruction, and no memory operand is involved.
        unsafe {
            asm!(
                "msr CNTP_TVAL_EL0, {interval}",
                "msr CNTP_CTL_EL0, {control}",
                "isb",
                interval = in(reg) interval,
                control = in(reg) CNTP_CTL_ENABLE,
                options(nostack, preserves_flags)
            );
        }
    }
}
/// Keep the device-tree pointer the boot protocol passed in `x0`.
///
/// Called from `boot.S` before the Rust entry, while BSS is already zeroed and
/// the boot stack is in place.  Storing it here is what lets the kernel find
/// the CPU list: without it the blob address stays zero, the flattened device
/// tree parses to nothing, and AP discovery concludes there is one CPU.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[no_mangle]
pub extern "C" fn aarch64_store_handoff(blob: usize) {
    crate::arch::boot::store_handoff_address(blob);
}

// The aarch64 boot protocol: what the firmware leaves in the registers, and
// how `_start` turns that into a call to the kernel.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("boot.S"));
