//! src/kernel/process/context.rs
//!
//! Architecture-independent CPU context storage for thread switching.
//!
//! The [`Context`] struct has a fixed layout shared by every architecture's
//! context-switch assembly:
//!
//! ```text
//!   offset 0:   instruction_pointer (usize)
//!   offset 8:   stack_pointer (usize)
//!   offset 16:  flags (usize)
//!   offset 24+: callee_saved [usize; 12]
//!   offset 160: simd_registers [u8; 256]
//! ```
//!
//! The callee-saved register area is 12 slots wide so that a single struct
//! serves all targets:
//!
//! - x86_64:  `rbx, rbp, r12, r13, r14, r15` (first 6 slots)
//! - aarch64: `x19 ..= x30` (12 slots)
//! - riscv64: `s0 ..= s11` (12 slots)
//!
//! The `_reserved` padding keeps the SIMD save area at offset 160 so the
//! switch assembly can hard-code its displacements.

use core::cell::UnsafeCell;

/// The number of callee-saved register slots shared by all architectures.
const CALLEE_SAVED_SLOTS: usize = 12;
/// Size of the SIMD register save area (16 × 16-byte XMM/Q registers).
const SIMD_REGISTER_AREA_SIZE: usize = 256;

/// The number of registers (plus flags) that precede the callee-saved area.
///
/// `instruction_pointer` (8) + `stack_pointer` (8) + `flags` (8) = 24 bytes.
/// SIMD state is saved at offset 160, so the padding between the end of the
/// callee-saved slots (120) and the SIMD area is 40 bytes = 5 usize slots.
const _: () = assert!(CALLEE_SAVED_SLOTS * 8 == 96);

/// A saved CPU context for one thread.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// Instruction pointer to resume at (x86_64 `rip`, aarch64 link/`pc`,
    /// riscv64 `ra`).
    pub instruction_pointer: usize,
    /// Stack pointer to restore (`rsp` / `sp` / `sp`).
    pub stack_pointer: usize,
    /// Processor flags (x86_64 `rflags`, aarch64 `DAIF`; unused on riscv64).
    pub flags: usize,
    /// Callee-saved general-purpose registers (layout per architecture, see
    /// the module docs).
    pub callee_saved: [usize; CALLEE_SAVED_SLOTS],
    /// Padding to keep [`Context::simd_registers`] at offset 160.
    _reserved: [usize; 5],
    /// SIMD / vector register save area.
    ///
    /// - x86_64:  16 × 16-byte `XMM0-XMM15` (256 bytes)
    /// - aarch64: 8 × 16-byte `Q8-Q15` (128 bytes used)
    /// - riscv64: unused (no FP/SIMD state is saved on switch)
    pub simd_registers: [u8; SIMD_REGISTER_AREA_SIZE],
}

impl Context {
    /// Create a zeroed context (used for the idle / dispatch thread).
    pub fn empty() -> Self {
        Self {
            instruction_pointer: 0,
            stack_pointer: 0,
            flags: 0,
            callee_saved: [0; CALLEE_SAVED_SLOTS],
            _reserved: [0; 5],
            simd_registers: [0; SIMD_REGISTER_AREA_SIZE],
        }
    }

    /// Create a context that will start executing at `instruction_pointer`.
    pub fn new(instruction_pointer: usize) -> Self {
        let mut context = Self::empty();
        context.instruction_pointer = instruction_pointer;
        context
    }

    /// Set the initial stack pointer for this context.
    pub fn set_stack_pointer(&mut self, stack_pointer: usize) {
        self.stack_pointer = stack_pointer;
    }

    /// The stack pointer saved in this context.
    pub fn stack_pointer(&self) -> usize {
        self.stack_pointer
    }

    /// The instruction pointer saved in this context.
    pub fn instruction_pointer(&self) -> usize {
        self.instruction_pointer
    }

    /// Byte offset of the SIMD register save area.
    ///
    /// x86_64 and aarch64 store SIMD state at offset 160; other targets (e.g.
    /// riscv64) have no SIMD save area and report 0.
    pub fn simd_offset(&self) -> usize {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            160
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }
}

pub struct ContextCell {
    inner: UnsafeCell<Context>,
}

// SAFETY: the context switch machinery serialises every access to the saved
// `Context` (interrupts disabled, a single thread owning the CPU at any
// instant, or the scheduler lock around dispatch), so sharing the cell across
// threads is sound — the same argument that justifies `SyncUnsafeCell`.
unsafe impl Sync for ContextCell {}

impl ContextCell {
    pub const fn new(context: Context) -> Self {
        Self {
            inner: UnsafeCell::new(context),
        }
    }

    pub fn get(&self) -> Context {
        unsafe { *self.inner.get() }
    }

    pub fn as_mut_ptr(&self) -> *mut Context {
        // Used by low-level switch assembly that mutates Context in place.
        self.inner.get()
    }

    pub fn as_ptr(&self) -> *const Context {
        self.inner.get()
    }
}
