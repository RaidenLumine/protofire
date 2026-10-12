//! src/arch/irq_handlers.rs
//!
//! Registry of what runs for a delivered interrupt identity.
//!
//! Message-signalled interrupts name their target by identity rather than by a
//! wire: RISC-V's IMSIC takes the identity in the data word of the message a
//! device writes, and AArch64's ITS translates a device's EventID into an LPI,
//! which is an identity too.  Both platforms need the same three things — a
//! window of identities a device may own, one handler per identity, and a
//! lookup that runs the handler an arriving message names — so the table and
//! the first-fit allocator that hands identities out live here instead of being
//! written once per architecture.
//!
//! The window belongs to the caller: RISC-V's device identities are 1..=254
//! and it indexes the table from zero, while an AArch64 LPI is 8192 plus an
//! offset.  `base` is what turns an architecture's identity into a slot here,
//! and an identity outside `base..base + IRQ_TABLE_LEN` is not this registry's
//! to answer.  Each base gets a **window** of its own, with its own slots, and
//! that is not tidiness: a slot is `identity - base`, so two bases answer to
//! the same slot number by arithmetic — an LPI 8193 (base 8192) and the
//! console UART's wired SPI 33 (base 32) are both slot 1 — and a registry
//! that shared one table would let whichever claim arrived first take the
//! interrupts of the other, so a delivered 33 ran the *message* device's
//! handler.

use alloc::sync::Arc;

use crate::kernel::sync::SpinLock;
use crate::Error;

/// What runs for a delivered interrupt identity.
pub type IrqHandler = Arc<dyn Fn(u32) + Send + Sync>;

/// Identities one window of the registry holds.
pub const IRQ_TABLE_LEN: usize = 256;

/// Windows one registry holds at once.
///
/// Four is the number of bases the tree names: RISC-V's identities indexed
/// from zero, AArch64's SPIs from 32, x86_64's message vectors from
/// `MSIX_VECTOR_BASE`, and AArch64's LPIs from `LPI_BASE`.  A machine opens
/// the windows its own controller claims identities in, at the first claim;
/// the host build's tests use three of the four.
const MAX_WINDOWS: usize = 4;

/// One window: the base it answers to, and its slots.
///
/// A window is opened by the first claim that names its base, because a
/// registration is what makes it exist; an identity is looked up in the
/// window its base names, and a base nobody has claimed in holds no slots.
struct Registry {
    /// The identity each window's first slot answers to; `None` is a window
    /// no claim has opened yet.
    bases: [Option<u32>; MAX_WINDOWS],
    handlers: [[Option<IrqHandler>; IRQ_TABLE_LEN]; MAX_WINDOWS],
}

/// A window with no handler registered in it.
const EMPTY_TABLE: [Option<IrqHandler>; IRQ_TABLE_LEN] = [const { None }; IRQ_TABLE_LEN];

impl Registry {
    const fn new() -> Self {
        Self {
            bases: [None; MAX_WINDOWS],
            handlers: [const { EMPTY_TABLE }; MAX_WINDOWS],
        }
    }

    /// The window `base` names, if it has one.
    fn window(&self, base: u32) -> Option<usize> {
        self.bases
            .iter()
            .position(|registered| *registered == Some(base))
    }

    /// The window `base` names, opening one for it if this is its first claim.
    ///
    /// `None` means every window is taken: the claim that found no window is
    /// refused rather than sharing a slot with a base that is not its own.
    fn open(&mut self, base: u32) -> Option<usize> {
        if let Some(window) = self.window(base) {
            return Some(window);
        }

        let window = self
            .bases
            .iter()
            .position(|registered| registered.is_none())?;
        self.bases[window] = Some(base);
        Some(window)
    }

    /// The slot an identity in `base..base + IRQ_TABLE_LEN` occupies.
    fn slot(&self, base: u32, identity: u32) -> Option<(usize, usize)> {
        let window = self.window(base)?;
        let offset = identity.checked_sub(base)? as usize;
        (offset < IRQ_TABLE_LEN).then_some((window, offset))
    }
}

/// The handler tables, one per window, indexed by identity minus that
/// window's base.
static IRQ_HANDLERS: SpinLock<Registry> = SpinLock::new(Registry::new());

/// Whether any handler is registered for `identity`.
pub fn is_registered(base: u32, identity: u32) -> bool {
    let registry = IRQ_HANDLERS.lock();
    match registry.slot(base, identity) {
        Some((window, offset)) => registry.handlers[window][offset].is_some(),
        None => false,
    }
}

/// Claim `count` consecutive identities for `handler`, and answer the first.
///
/// The run is allocated first-fit from `first` and never past `last`.  The
/// claim is all-or-nothing: either every identity in the run gets `handler`, or
/// nothing is written and the error says why.  That matters because the run is
/// what a device's MSI-X table is later programmed with — a half-claimed run
/// would move some of a device's messages to an identity nobody owns, which the
/// kernel would count as spurious.
///
/// A registration is a table entry, not a hardware access, so a driver claims
/// its identities at probe time and the table is programmed afterwards, once
/// the controller that carries the messages is up (the ITS, the IMSIC).
///
/// A window is opened for `base` by its first claim; a registry with no room
/// for another window refuses with [`Error::NoSpace`] rather than mixing two
/// bases into one slot space.
pub fn claim(
    base: u32,
    first: u32,
    last: u32,
    count: u32,
    handler: IrqHandler,
) -> Result<u32, Error> {
    claim_run(base, first, last, count, |_| Some(handler.clone()))
}

/// Claim `handlers.len()` consecutive identities, one handler each.
///
/// The sibling of [`claim`], for the case that made it necessary: a device
/// whose table delivers one identity per queue.  A driver that registers the
/// same handler for every queue cannot tell which queue completed, so its
/// completion path wakes on the device rather than on its own queue; naming
/// each identity is what lets the wakeup belong to the queue that caused it.
pub fn claim_each(base: u32, first: u32, last: u32, handlers: &[IrqHandler]) -> Result<u32, Error> {
    claim_run(base, first, last, handlers.len() as u32, |index| {
        handlers.get(index).cloned()
    })
}

/// The shared half of [`claim`] and [`claim_each`].
///
/// `handler_at` answers which handler the `index`-th identity of the run gets,
/// or `None` when the caller has none for it — which is a request the caller
/// made and cannot be honoured, so it is an argument error rather than a
/// partially registered run.
fn claim_run(
    base: u32,
    first: u32,
    last: u32,
    count: u32,
    handler_at: impl Fn(usize) -> Option<IrqHandler>,
) -> Result<u32, Error> {
    if count == 0 || first < base || last < first {
        return Err(Error::InvalidArgument);
    }

    // The window's own end is a bound like any other: an identity past it has
    // no slot, so a claim that would reach beyond both it and `last` is a claim
    // that cannot be honoured.
    let window_last = base.saturating_add(IRQ_TABLE_LEN as u32 - 1);
    let last = last.min(window_last);
    if last < first {
        return Err(Error::NoSpace);
    }

    // The handlers first, outside the registry's lock: a caller that is one
    // short is refused here, before anything is written, and the heap lock is
    // not taken under this one.
    let mut run: alloc::vec::Vec<IrqHandler> = alloc::vec::Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        run.push(handler_at(index).ok_or(Error::InvalidArgument)?);
    }

    let mut registry = IRQ_HANDLERS.lock();
    // The window this claim is in, opened by it if the base is new.  The
    // opening and the slots it guards are the same critical section: two
    // first claims of one base must not open two windows for it.
    let Some(window) = registry.open(base) else {
        return Err(Error::NoSpace);
    };
    // The last identity a run of `count` could start at.  A count larger than
    // the range itself is a request no window can honour, and the subtraction
    // is where that shows: `last` is an identity, not a length.
    let Some(last_first) = last.checked_sub(count - 1) else {
        return Err(Error::NoSpace);
    };
    let mut candidate = first;
    while candidate <= last_first {
        let free = (candidate..candidate + count)
            .all(|identity| registry.handlers[window][(identity - base) as usize].is_none());
        if free {
            for (offset, handler) in run.iter().enumerate() {
                registry.handlers[window][(candidate - base) as usize + offset] =
                    Some(handler.clone());
            }
            return Ok(candidate);
        }
        candidate += 1;
    }

    Err(Error::NoSpace)
}

/// Run the handler registered for `identity`.
///
/// The handler is cloned out of the table and the registry's lock dropped
/// before it runs, so a handler that registers another identity cannot
/// deadlock on the registry's own lock.  Answers whether a handler ran; an
/// identity nobody claimed — or one whose base names no window — is the
/// caller's to account for, and every caller does it the same way: as
/// spurious.
pub fn dispatch(base: u32, identity: u32) -> bool {
    let handler = {
        let registry = IRQ_HANDLERS.lock();
        let Some((window, offset)) = registry.slot(base, identity) else {
            return false;
        };
        registry.handlers[window][offset].clone()
    };

    match handler {
        Some(handler) => {
            handler(identity);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;

    use super::*;

    /// The registry is a static and the harness runs tests in parallel, so a
    /// claim is visible to every test in the run: each test owns identities no
    /// other test names, in a window the others do not fill — and the window
    /// set itself is shared, which is why no test opens a base another one
    /// needs room for.
    fn counting_handler(counter: &Arc<AtomicU32>) -> IrqHandler {
        let counter = counter.clone();
        Arc::new(move |_identity| {
            counter.fetch_add(1, Ordering::Relaxed);
        })
    }

    #[test]
    fn claim_answers_first_fit_runs_and_refuses_what_does_not_fit() {
        let counter = Arc::new(AtomicU32::new(0));
        let handler = counting_handler(&counter);

        assert_eq!(claim(0, 100, 110, 2, handler.clone()).unwrap(), 100);
        assert_eq!(claim(0, 100, 110, 2, handler.clone()).unwrap(), 102);
        assert_eq!(claim(0, 100, 110, 2, handler.clone()).unwrap(), 104);
        // 100..=110 is eleven identities, so a run of eight does not fit in
        // what is left of it.
        assert!(claim(0, 100, 110, 8, handler).is_err());
    }

    #[test]
    fn a_claim_never_returns_part_of_a_run() {
        let counter = Arc::new(AtomicU32::new(0));
        let handler = counting_handler(&counter);

        assert_eq!(claim(0, 120, 130, 1, handler.clone()).unwrap(), 120);
        // The first candidate is taken, so the run moves up intact.
        assert_eq!(claim(0, 120, 130, 2, handler.clone()).unwrap(), 121);
        assert!(claim(0, 120, 130, 12, handler.clone()).is_err());
        // Nothing was written by the failed claim: the next run still starts
        // straight after the last successful one.
        assert_eq!(claim(0, 120, 130, 1, handler).unwrap(), 123);
    }

    #[test]
    fn a_run_longer_than_its_window_is_refused_not_wrapped() {
        let counter = Arc::new(AtomicU32::new(0));
        let handler = counting_handler(&counter);

        // `last` is an identity, so a run of ten from a window that ends at
        // two is a request that cannot be honoured — and the arithmetic that
        // decides it must say so rather than wrap around a `u32`.
        assert!(claim(0, 1, 2, 10, handler.clone()).is_err());
        // The same shape at the window's own end: `last` is what the window
        // allows, not what the caller asked for.
        assert!(claim(0, 250, 0xffff_ffff, 20, handler.clone()).is_err());
        // Nothing was written by either refusal.
        assert!(!is_registered(0, 1));
        assert!(!is_registered(0, 250));
    }

    #[test]
    fn dispatch_runs_the_handler_an_identity_was_claimed_with() {
        let counter = Arc::new(AtomicU32::new(0));
        assert_eq!(
            claim(0, 140, 150, 1, counting_handler(&counter)).unwrap(),
            140
        );

        assert!(is_registered(0, 140));
        assert!(dispatch(0, 140));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        assert!(!is_registered(0, 141));
        assert!(!dispatch(0, 141));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn identities_outside_the_window_are_not_dispatched() {
        assert!(!dispatch(0, IRQ_TABLE_LEN as u32));
        assert!(!is_registered(0, IRQ_TABLE_LEN as u32));
        assert!(!dispatch(0, 0xffff_ffff));
        // A window above zero maps its own identities, and only those.
        assert!(!dispatch(8192, 140));
        assert!(!dispatch(8192, 8192 + IRQ_TABLE_LEN as u32));
    }

    #[test]
    fn a_window_shifts_which_identities_the_table_can_hold() {
        let counter = Arc::new(AtomicU32::new(0));
        assert!(claim(8192, 8000, 8000, 1, counting_handler(&counter)).is_err());
        assert_eq!(
            claim(8192, 8200, 8210, 1, counting_handler(&counter)).unwrap(),
            8200
        );
        assert!(dispatch(8192, 8200));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn windows_with_different_bases_answer_to_their_own_slots() {
        // The defect this test exists for: a slot is `identity - base`, so an
        // LPI 8193 (base 8192) and the console UART's wired SPI 33 (base 32)
        // are both slot 1.  While one table served both bases, the message
        // claim that arrived first took slot 1, the wired claim was refused,
        // and a delivered 33 ran the *message* device's handler — a real boot
        // printed `[virtio-blk] queue MSI (irq 33)` for a byte typed at the
        // console.  Each base has a window of its own now, and neither claim
        // can take the other's identity.
        let wired = Arc::new(AtomicU32::new(0));
        let message = Arc::new(AtomicU32::new(0));

        assert_eq!(
            claim(8192, 8193, 8193, 1, counting_handler(&message)).unwrap(),
            8193
        );
        assert_eq!(claim(32, 33, 33, 1, counting_handler(&wired)).unwrap(), 33);

        // The wired identity runs the wired handler, and only it.
        assert!(dispatch(32, 33));
        assert_eq!(wired.load(Ordering::Relaxed), 1);
        assert_eq!(message.load(Ordering::Relaxed), 0);

        // And the message identity still runs its own.
        assert!(dispatch(8192, 8193));
        assert_eq!(message.load(Ordering::Relaxed), 1);
    }
}
