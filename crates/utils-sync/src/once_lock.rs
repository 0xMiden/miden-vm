#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(feature = "std")]
use std::sync::OnceLock;

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;

/// A wrapper around `once_cell::race::OnceBox` that adds a `take()` method for cache invalidation.
///
/// `OnceBox` is designed to be write-once, but we need to be able to invalidate the cache
/// when the MAST forest is mutated. Since `take()` is only called with `&mut self`, we can
/// safely replace the entire `OnceBox` with a new empty one.
#[cfg(not(feature = "std"))]
pub struct OnceLockCompat<T> {
    inner: OnceBox<T>,
}

#[cfg(not(feature = "std"))]
impl<T> OnceLockCompat<T> {
    /// Creates a new empty `OnceLockCompat`.
    pub const fn new() -> Self {
        Self { inner: OnceBox::new() }
    }

    /// Gets the value if initialized, or initializes it with the provided closure.
    ///
    /// If multiple threads call this simultaneously, they may both execute the closure,
    /// but only one value will be stored. The losing thread's value will be immediately dropped.
    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        self.inner.get_or_init(|| alloc::boxed::Box::new(f()))
    }

    /// Takes the value out of the `OnceLockCompat`, leaving it empty.
    ///
    /// Returns `Some(T)` if the value was present, or `None` if it was not initialized.
    ///
    /// Note: For the no-std implementation, we can't extract the value from `OnceBox`,
    /// so we just replace it with a new empty one and return `None`.
    pub fn take(&mut self) -> Option<T> {
        // Replace the inner OnceBox with a new empty one.
        // This invalidates the cache by making the next `get_or_init` recompute.
        // We can't extract the value from OnceBox, so we just discard it.
        self.inner = OnceBox::new();
        None
    }
}

#[cfg(not(feature = "std"))]
impl<T> Default for OnceLockCompat<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "std"))]
impl<T> Clone for OnceLockCompat<T> {
    /// Cloning an `OnceLockCompat` creates a new empty `OnceLockCompat`.
    ///
    /// The cached value is not cloned because it's derived data that can be
    /// recomputed. This matches the semantics expected for cached/memoized values
    /// where the cache is an optimization detail, not part of the logical state.
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "std"))]
impl<T: fmt::Debug> fmt::Debug for OnceLockCompat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to OnceBox's Debug implementation
        self.inner.fmt(f)
    }
}

/// Type alias for std builds - uses `std::sync::OnceLock` directly
#[cfg(feature = "std")]
pub type OnceLockCompat<T> = OnceLock<T>;
