//! src/arch/riscv64/mod.rs
//!
//! RISC-V 64 architecture bring-up glue, platform hooks, and backend exports.

use core::arch::asm;
use core::fmt::Write;
use core::fmt::{self};
use core::ptr::read_volatile;
use core::ptr::write_volatile;

use crate::arch::Arch;
use crate::kernel::sync::SpinLock;

#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("trap.S"));

pub struct RiscV64;

/// Keep the boot hart ID and the device-tree pointer the platform handed over.
///
/// Called from `boot.S` before the Rust entry, the same way aarch64 does it
/// there.  `a0` is the hart the kernel is running on — not always hart 0, and
/// not readable from S-mode — and `a1` is the blob that tells the kernel how
/// many harts the machine has.  Without the address, `parse_fdt` sees nothing,
/// `cpu_count()` is zero, and `bring_up_aps` concludes there is one CPU and
/// starts none; everything the platform description carries (PCIe ECAM, IMSIC,
/// the timer rate) falls back to a hardcoded `virt` guess at the same time.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[no_mangle]
pub extern "C" fn riscv64_store_handoff(hartid: usize, blob: usize) {
    crate::arch::boot::store_handoff_address(blob);
    smp::store_boot_hart(hartid as u64);
}

impl Arch for RiscV64 {
    fn init_early() {
        trap::init();
        serial::init();
    }

    fn halt() {
        // SAFETY: `wfi` parks this hart until an interrupt and touches no
        // memory; supervisor mode may execute it unconditionally.
        unsafe {
            asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }

    fn reboot() -> ! {
        // On RISC-V S-mode, we can request a system reset via SBI SRST
        // (SRST extension, not always available), or loop forever.
        // The simplest fallback is halt + loop.
        loop {
            Self::halt();
        }
    }
}

pub mod interrupts {
    use core::arch::asm;

    pub fn are_enabled() -> bool {
        let sstatus: u64;
        // SAFETY: reading sstatus is a supervisor-CSR read with no memory side
        // effects.
        unsafe {
            asm!("csrr {sstatus}, sstatus", sstatus = out(reg) sstatus, options(nomem, nostack, preserves_flags));
        }
        // SIE (Supervisor Interrupt Enable) is bit 1 of sstatus.
        sstatus & (1 << 1) != 0
    }

    pub fn enable() {
        // SAFETY: setting SIE is a supervisor operation on this hart's own
        // status register; the caller is responsible for being ready to take an
        // interrupt.
        unsafe {
            // SIE (Supervisor Interrupt Enable) is bit 1 of sstatus.
            // Bit 0 is UIE — setting/clearing it would not gate interrupts.
            asm!("csrsi sstatus, 2", options(nomem, nostack, preserves_flags));
        }
    }

    pub fn disable() {
        // SAFETY: as `enable` — clearing SIE, which the caller pairs with a
        // later enable.
        unsafe {
            // SIE is bit 1 of sstatus (see `enable` above).
            asm!("csrci sstatus, 2", options(nomem, nostack, preserves_flags));
        }
    }
}

pub mod aia_imsic;
pub mod context;
pub mod cpufreq;
pub mod devices;
pub mod irq_balance;
pub mod mmu;
pub mod pci;
pub mod percpu;
pub mod rtc;
pub mod smp;
pub mod tlb;
pub mod trap;
pub mod user_access;

pub mod interrupt_controller {
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::Ordering;

    use super::read_volatile;
    use super::write_volatile;
    use crate::arch::interrupt_controller::InterruptController;

    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    const PLIC_QEMU_VIRT_BASE: usize = 0x0C00_0000;
    const PLIC_MAX_INTERRUPT_ID: u32 = 128;

    /// Return the PLIC base address, preferring FDT-discovered address.
    fn plic_base() -> usize {
        crate::arch::fdt::platform_info()
            .plic_base
            .unwrap_or(PLIC_QEMU_VIRT_BASE)
    }

    // ── Per-CPU PLIC context support ──────────────────────────────────
    //
    // The RISC-V PLIC assigns one S-mode context per hart.  On QEMU virt
    // the context number for hart N's S-mode is N * 2 + 1.

    /// Return the PLIC S-mode context number for a given logical CPU.
    fn plic_context_for_cpu(cpu_id: u32) -> u32 {
        cpu_id * 2 + 1
    }

    /// Return the PLIC context number for the current CPU.
    fn current_plic_context() -> u32 {
        crate::kernel::percpu::get().cpu_id * 2 + 1
    }

    fn plic_enable_addr(context: u32) -> usize {
        plic_base() + 0x002000 + context as usize * 0x80
    }

    /// Return the threshold register address for a given PLIC context.
    fn plic_threshold_addr(context: u32) -> usize {
        plic_base() + 0x200000 + context as usize * 0x1000
    }

    /// Return the claim/complete register address for a given PLIC context.
    fn plic_claim_addr(context: u32) -> usize {
        plic_base() + 0x200004 + context as usize * 0x1000
    }

    // ── Legacy helpers (used during boot before percpu is available) ──
    // These default to the BSP's S-mode context (hart 0, context 1).

    fn plic_priority_base() -> usize {
        plic_base()
    }

    fn plic_register(offset: usize) -> *mut u32 {
        offset as *mut u32
    }

    fn plic_read(offset: usize) -> u32 {
        // SAFETY: `offset` is a PLIC register address — the helpers above add
        // the platform's base to a register's own offset — and the PLIC sits in
        // the mapped device window.
        unsafe { read_volatile(plic_register(offset)) }
    }

    fn plic_write(offset: usize, value: u32) {
        // SAFETY: as `plic_read` — the same register block, on the write side.
        unsafe {
            write_volatile(plic_register(offset), value);
        }
    }

    /// Singleton PLIC controller used by the arch-level dispatch.
    pub static PLIC_CONTROLLER: PlicController = PlicController;

    /// RISC-V Platform-Level Interrupt Controller (PLIC).
    pub struct PlicController;

    impl InterruptController for PlicController {
        fn init(&self) {
            // Global init (once): priority registers.
            if !INITIALIZED.swap(true, Ordering::Acquire) {
                super::interrupts::disable();
                // Leave all priority registers at 0 (disabled by default).
            }

            // Per-CPU init: set threshold for the current CPU's PLIC context.
            let ctx = current_plic_context();
            plic_write(plic_threshold_addr(ctx), 0);
        }

        fn end_of_interrupt(&self, interrupt_id: u32) {
            if interrupt_id == 0 || interrupt_id > PLIC_MAX_INTERRUPT_ID {
                return;
            }
            // Write the completed interrupt ID to this CPU's claim/complete.
            let ctx = current_plic_context();
            plic_write(plic_claim_addr(ctx), interrupt_id);
        }

        fn enable_interrupt(&self, interrupt_id: u32) {
            if interrupt_id == 0 || interrupt_id > PLIC_MAX_INTERRUPT_ID {
                return;
            }

            // Enable the interrupt on every CPU's PLIC context so it can be
            // delivered to any hart.
            let cpu_count = crate::arch::fdt::cpu_count().max(1);
            for cpu_id in 0..cpu_count {
                let ctx = plic_context_for_cpu(cpu_id);
                let enable_offset = plic_enable_addr(ctx) + (interrupt_id as usize / 32) * 4;
                let bit = 1_u32 << (interrupt_id % 32);
                let current = plic_read(enable_offset);
                plic_write(enable_offset, current | bit);
            }
        }

        fn set_priority(&self, interrupt_id: u32, priority: u8) {
            if interrupt_id == 0 || interrupt_id > PLIC_MAX_INTERRUPT_ID {
                return;
            }

            let priority_offset = plic_priority_base() + interrupt_id as usize * 4;
            plic_write(priority_offset, priority as u32);
        }
    }

    /// Route an external interrupt to a single target hart.
    ///
    /// The PLIC only forwards an interrupt to a context that has its enable
    /// bit set, so routing is a per-context enable/disable: the target CPU's
    /// context gets the enable bit, every other online CPU's context loses
    /// it.  Used by the IRQ load balancer.
    pub(crate) fn set_irq_affinity(interrupt_id: u32, cpu_id: u32) {
        if interrupt_id == 0 || interrupt_id > PLIC_MAX_INTERRUPT_ID {
            return;
        }
        let cpu_count = crate::arch::fdt::cpu_count().max(1);
        for cpu in 0..cpu_count {
            let target = cpu == cpu_id;
            let ctx = plic_context_for_cpu(cpu);
            let enable_offset = plic_enable_addr(ctx) + (interrupt_id as usize / 32) * 4;
            let bit = 1_u32 << (interrupt_id % 32);
            let current = plic_read(enable_offset);
            let next = if target {
                current | bit
            } else {
                current & !bit
            };
            plic_write(enable_offset, next);
        }
    }

    /// Claim an interrupt from the PLIC on the current CPU's context.
    /// Returns the interrupt ID, or 0 if no interrupt is pending.
    pub(crate) fn claim_interrupt() -> u32 {
        let ctx = current_plic_context();
        plic_read(plic_claim_addr(ctx))
    }
}

pub mod serial {
    use super::fmt;
    use super::read_volatile;
    use super::write_volatile;
    use super::SpinLock;
    use super::Write;

    // QEMU `virt` platform: NS16550A UART at 0x1000_0000.
    const UART_QEMU_VIRT_BASE: usize = 0x1000_0000;

    fn uart_base() -> usize {
        crate::arch::fdt::platform_info()
            .uart_base
            .unwrap_or(UART_QEMU_VIRT_BASE)
    }

    // NS16550A register offsets (8-bit registers, but accessed as 32-bit on
    // some platforms; QEMU virt connects them as byte-accessible MMIO).
    const RBR_OFFSET: usize = 0x00; // Receiver Buffer (read)
    const THR_OFFSET: usize = 0x00; // Transmitter Holding (write)
    const IER_OFFSET: usize = 0x01; // Interrupt Enable
    const FCR_OFFSET: usize = 0x02; // FIFO Control
    const LCR_OFFSET: usize = 0x03; // Line Control
    const MCR_OFFSET: usize = 0x04; // Modem Control
    const LSR_OFFSET: usize = 0x05; // Line Status
    const DLL_OFFSET: usize = 0x00; // Divisor Latch LSB (DLAB=1)
    const DLM_OFFSET: usize = 0x01; // Divisor Latch MSB (DLAB=1)

    const LSR_THRE: u8 = 1 << 5; // Transmitter Holding Register Empty
    const LSR_DR: u8 = 1 << 0; // Data Ready

    const LCR_DLAB: u8 = 1 << 7; // Divisor Latch Access Bit
    const LCR_8N1: u8 = 0b11; // 8 data bits, no parity, 1 stop bit

    const UART_CLOCK: u32 = 1843200; // QEMU default UART clock
    const BAUD_RATE: u32 = 115200;

    struct Ns16550a {
        base: usize,
        initialized: bool,
    }

    impl Ns16550a {
        const fn new(base: usize) -> Self {
            Self {
                base,
                initialized: false,
            }
        }

        fn register(&self, offset: usize) -> *mut u8 {
            (self.base + offset) as *mut u8
        }

        fn read_u8(&self, offset: usize) -> u8 {
            // SAFETY: the NS16550A's register at `offset` from the base the
            // platform reported, inside the mapped device window.
            unsafe { read_volatile(self.register(offset)) }
        }

        fn write_u8(&self, offset: usize, value: u8) {
            // SAFETY: as `read_u8` — the same register, on the write side.
            unsafe {
                write_volatile(self.register(offset), value);
            }
        }

        fn init(&mut self) {
            // Disable interrupts.
            self.write_u8(IER_OFFSET, 0x00);

            // Set DLAB to configure baud rate.
            self.write_u8(LCR_OFFSET, LCR_DLAB);
            let divisor = (UART_CLOCK / (16 * BAUD_RATE)) as u16;
            self.write_u8(DLL_OFFSET, (divisor & 0xFF) as u8);
            self.write_u8(DLM_OFFSET, ((divisor >> 8) & 0xFF) as u8);

            // 8N1, clear DLAB.
            self.write_u8(LCR_OFFSET, LCR_8N1);

            // Enable and clear FIFOs (14-byte threshold).
            self.write_u8(FCR_OFFSET, 0x07);

            // No modem control signals needed.
            self.write_u8(MCR_OFFSET, 0x00);

            self.initialized = true;
        }

        fn write_byte(&mut self, byte: u8) {
            if !self.initialized {
                self.init();
            }

            // Wait for THRE.
            while self.read_u8(LSR_OFFSET) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }

            self.write_u8(THR_OFFSET, byte);
        }

        fn try_read_byte(&mut self) -> Option<u8> {
            if !self.initialized {
                self.init();
            }

            if self.read_u8(LSR_OFFSET) & LSR_DR == 0 {
                return None;
            }

            Some(self.read_u8(RBR_OFFSET))
        }
    }

    impl Write for Ns16550a {
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

    static SERIAL0: SpinLock<Ns16550a> = SpinLock::new(Ns16550a::new(UART_QEMU_VIRT_BASE));

    pub fn init() {
        let mut uart = SERIAL0.lock();
        uart.base = uart_base();
        uart.init();
    }

    pub fn write_str(message: &str) {
        let mut uart = SERIAL0.lock();
        if uart.initialized {
            let _ = uart.write_str(message);
        } else {
            drop(uart);
            for &byte in message.as_bytes() {
                if byte == b'\n' {
                    sbi_putchar(b'\r');
                }
                sbi_putchar(byte);
            }
        }
    }

    /// SBI legacy extension: write a character to the debug console.
    /// Used as a fallback when the NS16550A UART is not responding.
    /// a7 = 1 (sbi_putchar), a0 = character.
    fn sbi_putchar(c: u8) {
        // SAFETY: an SBI call with a documented extension and function ID,
        // passing one character in a0; no memory operand is involved.
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") 1usize,
                inlateout("a0") c as usize => _,
                // An SBI call preserves every register except `a0` and `a1`,
                // and OpenSBI uses both for its return value.  A register the
                // asm block does not mention is one the compiler is free to
                // keep a live value in across the `ecall` — so `a1` has to be
                // declared.  See `set_timer` for what that cost when it was
                // not.
                lateout("a1") _,
                options(nostack, preserves_flags)
            );
        }
    }

    pub fn write_byte(byte: u8) {
        // Try hardware UART first.  If the device hasn't been initialised
        // (no physical serial port) fall back to the SBI debug console.
        let mut uart = SERIAL0.lock();
        if uart.initialized {
            uart.write_byte(byte);
        } else {
            drop(uart);
            sbi_putchar(byte);
        }
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
    /// Set to true when the Sstc (Supervisor Timer Compare) extension is
    /// available, allowing direct `stimecmp` CSR access instead of SBI ecall.
    static SSTC_AVAILABLE: AtomicBool = AtomicBool::new(false);

    /// Non-standard SBI timer interrupt ID on QEMU virt.
    /// The PLIC does not route the timer interrupt; it uses the
    /// machine-level timer (mtime/mtimecmp) forwarded via SBI.
    /// Linux uses interrupt 5 for the supervisor timer on RISC-V.
    pub const TIMER_INTERRUPT_ID: u32 = 5;

    const TIMER_TICK_HZ: u32 = 100;

    // SBI extension IDs
    const SBI_EXT_TIME: u64 = 0x54494D45;

    // SBI time function IDs
    const SBI_SET_TIMER: u64 = 0;

    pub fn init() {
        if !INITIALIZED.swap(true, Ordering::Acquire) {
            // Global init (once): detect Sstc.
            if crate::arch::fdt::platform_info().has_sstc {
                SSTC_AVAILABLE.store(true, Ordering::Relaxed);
            }
            // Compute the timer interval.
            let interval = read_time_frequency() / TIMER_TICK_HZ as u64;
            TIMER_INTERVAL.store(interval, Ordering::Relaxed);
        }

        // Per-CPU init: enable the supervisor timer interrupt (STIE).
        //
        // `csrsi` takes only a 5-bit unsigned immediate, so it cannot reach
        // sie bit 5 (STIE) — an immediate of 5 sets bits 0 and 2 instead,
        // silently leaving the timer masked.  Load the bitmask into a
        // register and use the register form `csrs`.
        // SAFETY: setting the supervisor timer-interrupt bit of this hart's own
        // `sie`; the value is the register-form mask the comment above explains.
        unsafe {
            asm!(
                "csrs sie, {t}",
                t = in(reg) 1u64 << 5,
                options(nomem, nostack, preserves_flags)
            );
        }

        // Program the first tick.
        let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
        set_timer(read_time() + interval);
    }

    pub fn ticks() -> u64 {
        TICKS.load(Ordering::Relaxed)
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

    fn timer_interrupt_pending() -> bool {
        let sip: u64;
        // SAFETY: a supervisor-CSR read of the pending-interrupt register; no
        // memory side effects.
        unsafe {
            asm!("csrr {sip}, sip", sip = out(reg) sip, options(nomem, nostack, preserves_flags));
        }
        // STIP (Supervisor Timer Interrupt Pending) is bit 5.
        sip & (1 << 5) != 0
    }

    fn prepare_next_tick() -> u64 {
        let next_ticks = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
        let interval = TIMER_INTERVAL.load(Ordering::Relaxed).max(1);
        set_timer(read_time() + interval);
        next_ticks
    }

    fn read_time() -> u64 {
        let time: u64;
        // SAFETY: `time` is the platform's read-only counter, readable from
        // supervisor mode at any time.
        unsafe {
            asm!("csrr {time}, time", time = out(reg) time, options(nomem, nostack, preserves_flags));
        }
        time
    }

    fn read_time_frequency() -> u64 {
        // Prefer FDT-discovered frequency, fall back to QEMU virt default 10 MHz.
        crate::arch::fdt::platform_info()
            .timer_frequency
            .unwrap_or(10_000_000)
    }

    /// Program the next timer interrupt, using the Sstc `stimecmp` CSR when
    /// available (fast path, ~5 cycles) or falling back to SBI ecall (slow
    /// path, ~100 cycles).
    fn set_timer(stime_value: u64) {
        if SSTC_AVAILABLE.load(Ordering::Relaxed) {
            // SAFETY: `stimecmp` is only accessible when Sstc is detected
            // via the FDT ISA string and menvcfg.STCE is set by firmware.
            unsafe {
                asm!(
                    "csrw stimecmp, {val}",
                    val = in(reg) stime_value,
                    options(nomem, nostack, preserves_flags),
                );
            }
        } else {
            sbi_set_timer(stime_value);
        }
    }

    fn sbi_set_timer(stime_value: u64) {
        // SAFETY: as `sbi_putchar` — a documented SBI call, here with the
        // absolute time the next tick is due in a0.
        unsafe {
            asm!(
                "ecall",
                in("a7") SBI_EXT_TIME,
                in("a6") SBI_SET_TIMER,
                inlateout("a0") stime_value => _,
                // The SBI calling convention preserves every register except
                // `a0` and `a1`: firmware puts the error code and the return
                // value there.  Leaving `a1` unlisted told the compiler it
                // could keep a live value in it across the `ecall`, and
                // `prepare_next_tick` did exactly that — it held the new tick
                // count in `a1` while this call wiped it, so every interrupt
                // after the first reported tick 1.  The scheduler then never
                // saw a deadline elapse: timed waits never woke, `sleep` never
                // returned, and the riscv64 demo stopped at its first exit.
                lateout("a1") _,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

// The RISC-V boot protocol: what the firmware leaves in the registers, and
// how `_start` turns that into a call to the kernel.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("boot.S"));
