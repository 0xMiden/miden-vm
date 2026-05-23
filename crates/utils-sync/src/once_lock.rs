#[cfg(feature = "std")]
use std::sync::OnceLock;
#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;

use core::fmt;

/// A cache-invalidation wrapper with consistent semantics across std and no_std.
///
/// | Feature | Backing type |
/// |---------|-------------|
/// | `std`   | `std::sync::OnceLock<T>` |
/// | no_std  | `once_cell::race::OnceBox<T>` |
///
/// # Why not `Clone`?
///
/// Under `std`, `OnceLock::clone` copies the initialized value.
/// Under no_std, `OnceBox` does not support value extraction, so a "clone"
/// would silently produce an empty instance — a violation of the `Clone`
/// contract. `Clone` is therefore not implemented on either configuration.
/// If you need a fresh instance, call `OnceLockCompat::new()` explicitly.
pub struct OnceLockCompat<T> {
    #[cfg(feature = "std")]
    inner: OnceLock<T>,
    #[cfg(not(feature = "std"))]
    inner: OnceBox<T>,
}

impl<T> OnceLockCompat<T> {
    /// Creates a new, empty `OnceLockCompat`.
    pub const fn new() -> Self {
        #[cfg(feature = "std")]
        {
            Self {
                inner: OnceLock::new(),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Self {
                inner: OnceBox::new(),
            }
        }
    }

    /// Returns the value if already initialized, otherwise `None`.
    pub fn get(&self) -> Option<&T> {
        #[cfg(feature = "std")]
        {
            self.inner.get()
        }
        #[cfg(not(feature = "std"))]
        {
            // OnceBox::get() returns Option<&Box<T>>
            self.inner.get().map(|b| -> &T { b })
        }
    }

    /// Returns the value if initialized, or initializes it with `f`.
    ///
    /// If multiple threads race, each may execute `f`, but only one value is
    /// stored; the losers' values are dropped immediately.
    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        #[cfg(feature = "std")]
        {
            self.inner.get_or_init(f)
        }
        #[cfg(not(feature = "std"))]
        {
            // OnceBox::get_or_init() returns &Box<T>
            let b: &T = self.inner.get_or_init(|| alloc::boxed::Box::new(f()));
            b
        }
    }

    /// Invalidates the cache so the next [`get_or_init`](OnceLockCompat::get_or_init)
    /// recomputes the value.
    ///
    /// # no_std limitation
    ///
    /// Under no_std the backing `OnceBox` does not support extracting its value,
    /// so the stored value is **dropped** on reset and cannot be recovered.
    /// If you need the value before invalidating, call [`get`](OnceLockCompat::get) first.
    pub fn reset(&mut self) {
        #[cfg(feature = "std")]
        {
            self.inner = OnceLock::new();
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner = OnceBox::new();
        }
    }
}

impl<T> Default for OnceLockCompat<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceLockCompat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}
