use alloc::boxed::Box;
use core::{
    fmt,
    ops::Deref,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

/// Thread-safe, non-blocking, lazily evaluated lock with the same interface
/// as [`std::sync::LazyLock`].
///
/// Concurrent threads will race to set the value atomically, and memory allocated by losing threads
/// will be dropped immediately after they fail to set the pointer.
///
/// The underlying implementation is based on `once_cell::race::OnceBox` which relies on
/// [`core::sync::atomic::AtomicPtr`] to ensure that the data race results in a single successful
/// write to the relevant pointer, namely the first write.
/// See <https://github.com/matklad/once_cell/blob/v1.19.0/src/race.rs#L294>.
///
/// Performs lazy evaluation and can be used for statics.
pub struct RacyLock<T, F = fn() -> T>
where
    F: Fn() -> T,
{
    inner: AtomicPtr<T>,
    f: F,
}

impl<T, F> RacyLock<T, F>
where
    F: Fn() -> T,
{
    /// Creates a new lazy, racy value with the given initializing function.
    pub const fn new(f: F) -> Self {
        Self {
            inner: AtomicPtr::new(ptr::null_mut()),
            f,
        }
    }

    /// Forces the evaluation of the locked value and returns a reference to
    /// the result. This is equivalent to the [`Self::deref`].
    ///
    /// There is no blocking involved in this operation. Instead, concurrent
    /// threads will race to set the underlying pointer. Memory allocated by
    /// losing threads will be dropped immediately after they fail to set the pointer.
    ///
    /// This function's interface is designed around [`std::sync::LazyLock::force`] but
    /// the implementation is derived from `once_cell::race::OnceBox::get_or_try_init`.
    pub fn force(this: &RacyLock<T, F>) -> &T {
        let mut ptr = this.inner.load(Ordering::Acquire);

        // Pointer is not yet set, attempt to set it ourselves.
        if ptr.is_null() {
            // Execute the initialization function and allocate.
            let val = (this.f)();
            ptr = Box::into_raw(Box::new(val));

            // Attempt atomic store.
            let exchange = this.inner.compare_exchange(
                ptr::null_mut(),
                ptr,
                Ordering::AcqRel,
                Ordering::Acquire,
            );

            // Pointer already set, load.
            if let Err(old) = exchange {
                drop(unsafe { Box::from_raw(ptr) });
                ptr = old;
            }
        }

        unsafe { &*ptr }
    }
}

impl<T: Default> Default for RacyLock<T> {
    /// Creates a new lock that will evaluate the underlying value based on `T::default`.
    #[inline]
    fn default() -> RacyLock<T> {
        RacyLock::new(T::default)
    }
}

impl<T, F> fmt::Debug for RacyLock<T, F>
where
    T: fmt::Debug,
    F: Fn() -> T,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RacyLock({:?})", self.inner.load(Ordering::Relaxed))
    }
}

impl<T, F> Deref for RacyLock<T, F>
where
    F: Fn() -> T,
{
    type Target = T;

    /// Either sets or retrieves the value, and dereferences it.
    ///
    /// See [`Self::force`] for more details.
    #[inline]
    fn deref(&self) -> &T {
        RacyLock::force(self)
    }
}

impl<T, F> Drop for RacyLock<T, F>
where
    F: Fn() -> T,
{
    /// Drops the underlying pointer.
    fn drop(&mut self) {
        let ptr = *self.inner.get_mut();
        if !ptr.is_null() {
            // SAFETY: for any given value of `ptr`, we are guaranteed to have at most a single
            // instance of `RacyLock` holding that value. Hence, synchronizing threads
            // in `drop()` is not necessary, and we are guaranteed never to double-free.
            // In short, since `RacyLock` doesn't implement `Clone`, the only scenario
            // where there can be multiple instances of `RacyLock` across multiple threads
            // referring to the same `ptr` value is when `RacyLock` is used in a static variable.
            drop(unsafe { Box::from_raw(ptr) });
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn deref_default() {
        // Lock a copy type and validate default value.
        let lock: RacyLock<i32> = RacyLock::default();
        assert_eq!(*lock, 0);
    }

    #[test]
    fn deref_copy() {
        // Lock a copy type and validate value.
        let lock = RacyLock::new(|| 42);
        assert_eq!(*lock, 42);
    }

    #[test]
    fn deref_clone() {
        // Lock a no copy type.
        let lock = RacyLock::new(|| Vec::from([1, 2, 3]));

        // Use the value so that the compiler forces us to clone.
        let mut v = lock.clone();
        v.push(4);

        // Validate the value.
        assert_eq!(v, Vec::from([1, 2, 3, 4]));
    }

    #[test]
    fn deref_static() {
        // Create a static lock.
        static VEC: RacyLock<Vec<i32>> = RacyLock::new(|| Vec::from([1, 2, 3]));

        // Validate that the address of the value does not change.
        let addr = &*VEC as *const Vec<i32>;
        for _ in 0..5 {
            assert_eq!(*VEC, [1, 2, 3]);
            assert_eq!(addr, &(*VEC) as *const Vec<i32>)
        }
    }

    #[test]
    fn type_inference() {
        // Check that we can infer `T` from closure's type.
        let _ = RacyLock::new(|| ());
    }

    #[test]
    fn is_sync_send() {
        fn assert_traits<T: Send + Sync>() {}
        assert_traits::<RacyLock<Vec<i32>>>();
    }
}
