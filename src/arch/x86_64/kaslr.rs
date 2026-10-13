//! src/arch/x86_64/kaslr.rs
//!
//! Kernel Address Space Layout Randomisation for x86_64 — the boot-time
//! relocator.
//!
//! ## What this does
//!
//! With the `kaslr` feature on, the first thing `kernel_entry` does is
//! relocate the kernel: the loaded image is copied to a 2 MiB-aligned base
//! inside RAM the machine describes as available, the relocation table's
//! sites are patched by the delta, `rsp` moves into the copy's own boot
//! stack, and control jumps into the copy — the image the loader placed is
//! never entered again.  The continuation
//! ([`crate::arch::entry::kernel_entry_relocated`]) runs entirely from the
//! copy, so every address the rest of the kernel reads is naturally the
//! copy's own.
//!
//! The table is what makes that work, and it is proven, not heuristical:
//! `gen-kaslr-relocs` keeps a site only when the bytes there are a symbol's
//! address plus the record's addend, and `make check-kaslr-relocs` holds it
//! to the addresses the kernel stores.  A `mov $0x2489c000` the compiler
//! folded from `__bss_end + 0x1000` is in the table, so the copy's load of
//! that immediate yields the copy's own `__bss_end + 0x1000`.  Values
//! computed from symbols — page-table plans, pool bounds, heap bounds — are
//! correct in the copy for the same reason; nothing needs a "delta" plumbed
//! through it.  The one delta that travels is the one this module stores for
//! its own report.
//!
//! ## The window, and why it is where it is
//!
//! A placement must satisfy four bounds at once:
//!
//! * it must not overlap the image already running, whose bytes are the source
//!   of the copy (so `base` starts after `__image_end`);
//! * the copy and the whole kernel span after it — the image's reserved demo
//!   slots and the 512 MiB frame pool — must stay below the stack window's base
//!   (`X86_STACK_WINDOW_BASE`), because the runtime page tables map the
//!   kernel's `bss` range (which ends at `__kernel_end`, after the pool) and
//!   the stack window at fixed addresses; a span that crossed it would collide
//!   with the window's own mapping;
//! * the whole span must stay under `KERNEL_IDENTITY_MEMORY_END` (1 GiB), which
//!   is what `phys_addr_of` answers for, what the static runtime tables can
//!   name, and what keeps every frame a device can address;
//! * both the copy and the pool's new start must land inside regions the
//!   machine calls available.
//!
//! On a 1 GiB `q35` machine those constraints leave fifty-odd 2 MiB slots
//! (measured: 56 for the demo build), and the boot picks one from the
//! time-stamp counter.  A
//! machine with less RAM, or one that describes nothing, gets no placement:
//! the boot says so and stays where the loader put it, which is the same
//! kernel without the randomisation.
//!
//! ## What is verified, and what is not
//!
//! `make check-x8664-kaslr-runtime` regenerates the table from the built image
//! and requires it to equal the tracked one (so the table describes the image
//! it is compiled into), boots the result and asserts the relocation line
//! with a nonzero delta, the image and pool ranges at their relocated
//! addresses, the demo shell and a typed answer; it boots a four-CPU machine
//! and requires the APs to come online in the copy and dispatch threads (the
//! trampoline's one link-time value is `ap_entry`'s address, and that site is
//! in the table); and it boots a 128 MiB machine, which has no room for the
//! copy, to require the refusal and a shell at the link address.
//!
//! Not verified: a loader that does **not** place the kernel at its link
//! address, which the relocator assumes (every loader this tree has used
//! does), and placement on a machine whose usable RAM has holes the window
//! cannot avoid — the candidate search checks the regions, but no gate boots
//! such a machine.

#[cfg(feature = "kaslr")]
use core::ptr;

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// The KASLR relocation table, generated from the built image and proven
/// against it by `make check-kaslr-relocs`.
#[cfg(feature = "kaslr")]
mod table {
    include!("kaslr_relocs.generated.rs");
}

/// Where this boot put the kernel, and the delta its sites were patched by;
/// 0 means the link address.
static RELOCATED_BASE: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "kaslr")]
static RELOCATION_DELTA: AtomicUsize = AtomicUsize::new(0);

/// Record what the relocator did, from the continuation that runs in the
/// copy.  Written through the copy's own statics: this function is the first
/// thing the copy executes, so its data lives there.
#[cfg(feature = "kaslr")]
pub(crate) fn record_relocation(base: usize, delta: usize) {
    RELOCATION_DELTA.store(delta, Ordering::Release);
    RELOCATED_BASE.store(base, Ordering::Release);
}

/// Where this boot runs the kernel, or `None` at the link address.
pub fn relocated_base() -> Option<usize> {
    match RELOCATED_BASE.load(Ordering::Acquire) {
        0 => None,
        base => Some(base),
    }
}

/// Whether this invocation is running from a KASLR-relocated image.
pub fn is_relocated() -> bool {
    relocated_base().is_some()
}

/// Say where this boot put the kernel, from `boot_kernel` once the console
/// exists.  The relocator itself runs before the console — the earliest code
/// there is — so this is the line its decision appears on.
#[cfg(feature = "kaslr")]
pub(crate) fn announce() {
    // The kernel's `println!` expands to a statement (it carries a trailing
    // semicolon), so it cannot stand in a match arm's expression position.
    if let Some(base) = relocated_base() {
        crate::println!(
            "[kaslr ] relocated to {:#x} (delta {:#x})",
            base,
            RELOCATION_DELTA.load(Ordering::Acquire)
        );
    } else {
        crate::println!(
            "[kaslr ] no placement in the machine's memory; booting at the link address"
        );
    }
}

#[cfg(feature = "kaslr")]
unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
    static __image_end: u8;
    static __bss_start: u8;
    static __pool_start: u8;
    static boot_stack_top: u8;
}

/// Relocate the image, or return and let the boot continue at the link
/// address.
///
/// Returns only when no placement could be found — a machine whose memory
/// has no room for the kernel's whole span, or one that describes nothing.
/// When it finds one, this never returns: control leaves through the copy's
/// own entry (see the module comment).
#[cfg(feature = "kaslr")]
pub(crate) fn relocate_or_continue(magic: u32, info: u32) {
    // `addr_of!` on a linker symbol is safe (nothing is read); the copy below
    // writes only into RAM `choose_placement` checked.
    let kernel_start = ptr::addr_of!(__kernel_start) as usize;
    let kernel_end = ptr::addr_of!(__kernel_end) as usize;
    let image_end = ptr::addr_of!(__image_end) as usize;
    let bss_start = ptr::addr_of!(__bss_start) as usize;
    let pool_start = ptr::addr_of!(__pool_start) as usize;
    let stack_top = ptr::addr_of!(boot_stack_top) as usize;

    let Some(base) = choose_placement(
        magic,
        info as usize,
        kernel_start,
        kernel_end,
        image_end,
        pool_start,
    ) else {
        return;
    };
    let delta = base - kernel_start;
    let copy_span = image_end - kernel_start;

    // SAFETY: `base` is 2 MiB-aligned RAM the machine describes as available
    // and clear of the running image, so source and destination are distinct
    // ranges inside the identity map this boot runs under.  The relocation
    // sites were proven by the generator before the table was compiled in;
    // the jump target is the same function in the copy, at the offset the
    // linker gave it.
    unsafe {
        ptr::copy_nonoverlapping(kernel_start as *const u8, base as *mut u8, copy_span);
        // The copied `.bss` tail is the new image's zeroed storage — the
        // loader zeroed the old copy's, and a byte copy would have carried
        // whatever was there.
        ptr::write_bytes(
            (base + (bss_start - kernel_start)) as *mut u8,
            0,
            image_end - bss_start,
        );
        apply_relocations(base, delta);

        let target = base
            + (crate::arch::entry::kernel_entry_relocated as *const () as usize - kernel_start);
        let new_stack = base + (stack_top - kernel_start);
        core::arch::asm!(
            "mov rsp, {stack}",
            "jmp {target}",
            stack = in(reg) new_stack,
            target = in(reg) target,
            in("rdi") base,
            in("rsi") delta,
            in("edx") magic,
            in("ecx") info,
            options(noreturn)
        );
    }
}

/// Patch every proven site in the copy by `delta`.
#[cfg(feature = "kaslr")]
unsafe fn apply_relocations(base: usize, delta: usize) {
    let entries = &table::KASLR_RELOCATIONS[..table::KASLR_RELOCATION_COUNT];
    for &(offset, _addend, width) in entries {
        // SAFETY: every entry is a site the generator proved is an address
        // (site == symbol + addend) and the copy spans exactly the image the
        // table was generated from, so each site is inside the copy; the
        // width is the one the record was proven at, and unaligned accesses
        // are used because an instruction immediate carries no alignment
        // promise.
        unsafe {
            let site = base + offset;
            match width {
                4 => {
                    let value = ptr::read_unaligned(site as *const u32);
                    ptr::write_unaligned(site as *mut u32, value.wrapping_add(delta as u32));
                }
                8 => {
                    let value = ptr::read_unaligned(site as *const u64);
                    ptr::write_unaligned(site as *mut u64, value.wrapping_add(delta as u64));
                }
                // A width from a proven record is 4 or 8; the padding slots
                // past `KASLR_RELOCATION_COUNT` are never in `entries`.
                _ => {}
            }
        }
    }
}

/// Pick the base to move the kernel to: a 2 MiB-aligned address that keeps
/// the copy and the whole span after it inside what the kernel's own memory
/// can be, on RAM the machine calls available, drawn from the time-stamp
/// counter so two boots of one binary can differ.
///
/// The bounds are the four in the module comment, in the order they can
/// exclude: the copy starts after the running image, the whole kernel span
/// stays below the stack window and below `KERNEL_IDENTITY_MEMORY_END`, and
/// both the copy and the pool's new start land in available regions.
#[cfg(feature = "kaslr")]
fn choose_placement(
    magic: u32,
    info: usize,
    kernel_start: usize,
    kernel_end: usize,
    image_end: usize,
    pool_start: usize,
) -> Option<usize> {
    use crate::arch::boot::MemoryRegion;
    use crate::arch::boot::MEMORY_REGION_AVAILABLE;
    use crate::arch::x86_64::paging::KERNEL_IDENTITY_MEMORY_END;
    use crate::arch::x86_64::paging::X86_STACK_WINDOW_BASE;

    const STEP: usize = 2 * 1024 * 1024;

    let regions: alloc::vec::Vec<MemoryRegion> =
        crate::arch::boot::memory_regions_for_handoff(magic, info)?;

    let copy_span = image_end - kernel_start;
    let total_span = kernel_end - kernel_start;
    let pool_offset = pool_start - kernel_start;

    // Below the stack window and below the identity bound; whichever is
    // nearer is the ceiling for the *end* of the kernel's span.
    let ceiling = X86_STACK_WINDOW_BASE.min(KERNEL_IDENTITY_MEMORY_END);
    let bottom = image_end.next_multiple_of(STEP);
    let top = ceiling.checked_sub(total_span)? & !(STEP - 1);
    if top < bottom {
        return None;
    }
    let candidates = (top - bottom) / STEP + 1;

    let inside_available = |start: usize, end: usize| {
        regions.iter().any(|region| {
            region.kind == MEMORY_REGION_AVAILABLE && region.base <= start && end <= region.end()
        })
    };

    let seed = entropy();
    for index in 0..candidates {
        let base = bottom + ((seed + index) % candidates) * STEP;
        if !inside_available(base, base + copy_span) {
            continue;
        }
        // The pool moves with the kernel (its bounds are linker symbols the
        // table patches), and it must still have a frame the allocator may
        // manage: its start has to sit inside real RAM, or the boot refuses
        // at `[mem   ]` with "the pool starts past the memory the machine
        // describes".
        if !inside_available(
            base + pool_offset,
            base + pool_offset + crate::memory::frame::FRAME_SIZE,
        ) {
            continue;
        }
        return Some(base);
    }
    None
}

/// Entropy for the placement: the time-stamp counter, mixed so its low bits
/// are usable as an index.  A machine whose TSC reads the same every boot
/// (or reads zero) gets a fixed placement — the mechanism is exercised
/// either way, and no promise about unpredictability is made here.
#[cfg(feature = "kaslr")]
fn entropy() -> usize {
    // SAFETY: `rdtsc` reads the cycle counter; it touches no memory and is
    // available on every machine this kernel boots on.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    (tsc as usize).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 17
}
