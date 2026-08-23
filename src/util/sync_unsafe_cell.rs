//! src/util/sync_unsafe_cell.rs
//! A `Sync`-capable `UnsafeCell` wrapper for kernel statics.
//!
//! A bare `UnsafeCell<T>` is `!Sync`, so it cannot appear in `static`
//! items.  Architecture code (GDT, IDT, per-AP stacks, spin tables) needs
//! mutable cell-like statics whose access is serialised by the surrounding
//! unsafe code (interrupts disabled, single boot CPU, explicit barriers).
//! This type opts into `Sync` explicitly: soundness rests on the caller
//! guaranteeing that no two threads access the cell concurrently.

use core::cell::UnsafeCell;

/// A `Sync`-capable wrapper around [`UnsafeCell`].
#[repr(transparent)]
pub struct SyncUnsafeCell<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: access through the cell is always `unsafe`; the type exists
// precisely so kernel statics can opt into `Sync` while keeping every
// mutation behind an unsafe block that the caller must synchronise.
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    /// Create a new cell holding `value`.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
        }
    }

    /// Get a raw mutable pointer to the inner value.
    #[inline]
    pub fn get(&self) -> *mut T {
        self.inner.get()
    }

    /// Read the inner value by copying it out.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no concurrent write is in flight.
    /// In a single-threaded kernel this is trivially satisfied.
    #[inline]
    pub unsafe fn read(&self) -> T
    where
        T: Copy,
    {
        // SAFETY: caller guarantees no concurrent writes.
        unsafe { core::ptr::read(self.inner.get()) }
    }

    /// Write `value` into the cell.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no concurrent read or write is in
    /// flight (e.g. interrupts disabled or single CPU).
    #[inline]
    pub unsafe fn write(&self, value: T) {
        // SAFETY: caller guarantees exclusive access.
        unsafe { core::ptr::write(self.inner.get(), value) }
    }

    /// Get an immutable reference to the inner value.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent mutation is in flight.
    #[inline]
    pub unsafe fn get_ref(&self) -> &T {
        // SAFETY: caller guarantees exclusive read access.
        unsafe { &*self.inner.get() }
    }

    /// Get a mutable reference to the inner value.
    ///
    /// Requires exclusive (`&mut self`) access to the cell itself.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Replace the inner value, returning the previous value.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent access is in flight.
    #[inline]
    pub unsafe fn replace(&self, value: T) -> T {
        // SAFETY: caller guarantees exclusive access.
        unsafe { core::ptr::replace(self.inner.get(), value) }
    }
}

impl<T: Default> Default for SyncUnsafeCell<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for SyncUnsafeCell<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SAFETY: formatting requires no concurrent mutation by convention.
        unsafe {
            f.debug_struct("SyncUnsafeCell")
                .field("value", &*self.inner.get())
                .finish()
        }
    }
}
