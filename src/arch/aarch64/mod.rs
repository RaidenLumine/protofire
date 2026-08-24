//! src/arch/aarch64/mod.rs
//!
//! AArch64 architecture bring-up glue, platform hooks, and backend exports.

use core::arch::asm;
use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};

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

        unsafe {
            asm!("mrs {daif}, DAIF", daif = out(reg) daif, options(nomem, nostack, preserves_flags));
        }

        daif & (1 << 7) == 0
    }

    pub fn enable() {
        unsafe {
            asm!(
                "msr DAIFClr, #0xf",
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    pub fn disable() {
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
pub(crate) mod exception;
pub mod irq_balance;
pub mod mmu;
pub mod pci;
pub mod psci;
pub mod rand;
pub mod rtc;
pub mod trap;
pub mod user_access;

pub(crate) mod smp;

pub mod interrupt_controller {
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::{read_volatile, write_volatile};
    use crate::arch::interrupt_controller::InterruptController;

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    const GICD_BASE_DEFAULT: usize = 0x0800_0000;
    const GICC_BASE_DEFAULT: usize = 0x0801_0000;

    fn gicd_base() -> usize {
        crate::arch::fdt::platform_info()
            .gicd_base
            .unwrap_or(GICD_BASE_DEFAULT)
    }

    fn gicc_base() -> usize {
        crate::arch::fdt::platform_info()
            .gicc_base
            .unwrap_or(GICC_BASE_DEFAULT)
    }

    const GICD_CTLR: usize = 0x000;
    const GICD_IGROUPR0: usize = 0x080;
    const GICD_ISENABLER0: usize = 0x100;
    const GICD_ICPENDR0: usize = 0x280;
    const GICD_IPRIORITYR: usize = 0x400;
    const GICD_ITARGETSR: usize = 0x1800;

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
        unsafe { read_volatile(distributor_register(offset)) }
    }

    fn distributor_write(offset: usize, value: u32) {
        unsafe {
            write_volatile(distributor_register(offset), value);
        }
    }

    fn cpu_interface_read(offset: usize) -> u32 {
        unsafe { read_volatile(cpu_interface_register(offset)) }
    }

    fn cpu_interface_write(offset: usize, value: u32) {
        unsafe {
            write_volatile(cpu_interface_register(offset), value);
        }
    }

    fn priority_register(interrupt_id: u32) -> *mut u8 {
        (gicd_base() + GICD_IPRIORITYR + interrupt_id as usize) as *mut u8
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

            // Reprogram the distributor and CPU interface atomically with local IRQs masked.
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
            unsafe {
                write_volatile(priority_register(interrupt_id), priority);
            }
        }
    }

    // -- GIC-specific helpers that are not part of the generic trait ---------

    /// Return the active interrupt controller singleton for this platform.
    pub(crate) fn active_controller() -> &'static dyn InterruptController {
        &GICV2_CONTROLLER
    }

    /// Per-CPU GIC CPU interface initialisation (called on each AP).
    pub(crate) fn init_gicc() {
        cpu_interface_write(GICC_PMR, 0xFF);
        cpu_interface_write(GICC_BPR, 0);
        cpu_interface_write(GICC_CTLR, GIC_ENABLE_GROUP0 | GIC_ENABLE_GROUP1);
    }

    pub(crate) fn set_group1(interrupt_id: u32) {
        let register = GICD_IGROUPR0 + ((interrupt_id as usize / 32) * 4);
        let bit = 1_u32 << (interrupt_id % 32);
        let value = distributor_read(register) | bit;
        distributor_write(register, value);
    }

    /// Re-target an SPI (interrupt id >= 32) to a specific CPU.
    ///
    /// GICv2 routes SPIs via the per-interrupt ITARGETSR byte (GICD base +
    /// 0x1800 + id), whose low bits are a CPU bitmask.  SGIs and PPIs
    /// (ids < 32) are per-CPU by design and cannot be re-targeted; the
    /// caller (irq_balance) checks routability before invoking this.
    pub(crate) fn set_irq_affinity(interrupt_id: u32, cpu_id: u32) {
        if interrupt_id < 32 {
            return;
        }
        let mask = 1_u8 << (cpu_id % 8);
        let register = (gicd_base() + GICD_ITARGETSR + interrupt_id as usize) as *mut u8;
        unsafe {
            write_volatile(register, mask);
        }
    }

    pub(crate) fn claim_interrupt() -> Option<u32> {
        let acknowledge = cpu_interface_read(GICC_IAR);
        (interrupt_id(acknowledge) < SPURIOUS_INTERRUPT_ID_START).then_some(acknowledge)
    }

    pub(crate) fn interrupt_id(acknowledge: u32) -> u32 {
        acknowledge & 0x03ff
    }

    /// Legacy: write EOI to the GIC CPU interface.
    ///
    /// Prefer `InterruptController::end_of_interrupt` through the dispatch
    /// layer.  This function remains for backward compatibility.
    pub(crate) fn acknowledge(acknowledge: u32) {
        GICV2_CONTROLLER.end_of_interrupt(acknowledge);
    }
}

pub mod serial {
    use super::{fmt, read_volatile, write_volatile, SpinLock, Write};

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
            unsafe { read_volatile(self.register(offset)) }
        }

        fn write(&self, offset: usize, value: u32) {
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
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
