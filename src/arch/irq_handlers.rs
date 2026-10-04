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
//! to answer.

use alloc::sync::Arc;

use crate::kernel::sync::SpinLock;
use crate::Error;

/// What runs for a delivered interrupt identity.
pub type IrqHandler = Arc<dyn Fn(u32) + Send + Sync>;

/// Identities one registry holds.
pub const IRQ_TABLE_LEN: usize = 256;

/// The handler table, indexed by identity minus the caller's window base.
static IRQ_HANDLERS: SpinLock<[Option<IrqHandler>; IRQ_TABLE_LEN]> =
    SpinLock::new([const { None }; IRQ_TABLE_LEN]);

/// The table slot an identity in `base..base + IRQ_TABLE_LEN` occupies.
fn slot(base: u32, identity: u32) -> Option<usize> {
    let offset = identity.checked_sub(base)? as usize;
    (offset < IRQ_TABLE_LEN).then_some(offset)
}

/// Whether any handler is registered for `identity`.
pub fn is_registered(base: u32, identity: u32) -> bool {
    match slot(base, identity) {
        Some(index) => IRQ_HANDLERS.lock()[index].is_some(),
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
pub fn claim(
    base: u32,
    first: u32,
    last: u32,
    count: u32,
    handler: IrqHandler,
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

    let mut handlers = IRQ_HANDLERS.lock();
    // The last identity a run of `count` could start at.  A count larger than
    // the range itself is a request no window can honour, and the subtraction
    // is where that shows: `last` is an identity, not a length.
    let Some(last_first) = last.checked_sub(count - 1) else {
        return Err(Error::NoSpace);
    };
    let mut candidate = first;
    while candidate <= last_first {
        let free = (candidate..candidate + count)
            .all(|identity| handlers[(identity - base) as usize].is_none());
        if free {
            for identity in candidate..candidate + count {
                handlers[(identity - base) as usize] = Some(handler.clone());
            }
            return Ok(candidate);
        }
        candidate += 1;
    }

    Err(Error::NoSpace)
}

/// Run the handler registered for `identity`.
///
/// The handler is taken out of the table before it is called, so a handler that
/// registers another identity cannot deadlock on the registry's own lock.
/// Answers whether a handler ran; an identity nobody claimed is the caller's to
/// account for, and every caller does it the same way — as spurious.
pub fn dispatch(base: u32, identity: u32) -> bool {
    let Some(index) = slot(base, identity) else {
        return false;
    };

    let handler = IRQ_HANDLERS.lock()[index].clone();
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

    /// Each test owns a slice of the table, because the registry is a static
    /// and the harness runs tests in parallel: two tests claiming in the same
    /// run would see each other's claims.
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
}
