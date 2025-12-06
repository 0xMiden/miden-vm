#[cfg(not(loom))]
use core::{
    hint,
    sync::atomic::{AtomicUsize, Ordering},
};

use lock_api::RawRwLock;
#[cfg(loom)]
use loom::{
    hint,
    sync::atomic::{AtomicUsize, Ordering},
};

/// An implementation of a reader-writer lock, based on a spinlock primitive, no-std compatible
///
/// See [lock_api::RwLock] for usage.
pub type RwLock<T> = lock_api::RwLock<Spinlock, T>;

/// See [lock_api::RwLockReadGuard] for usage.
pub type RwLockReadGuard<'a, T> = lock_api::RwLockReadGuard<'a, Spinlock, T>;

/// See [lock_api::RwLockWriteGuard] for usage.
pub type RwLockWriteGuard<'a, T> = lock_api::RwLockWriteGuard<'a, Spinlock, T>;

/// The underlying raw reader-writer primitive that implements [lock_api::RawRwLock]
///
/// This is fundamentally a spinlock, in that blocking operations on the lock will spin until
/// they succeed in acquiring/releasing the lock.
///
/// To achieve the ability to share the underlying data with multiple readers, or hold
/// exclusive access for one writer, the lock state is based on a "locked" count, where shared
/// access increments the count by an even number, and acquiring exclusive access relies on the
/// use of the lowest order bit to stop further shared acquisition, and indicate that the lock
/// is exclusively held (the difference between the two is irrelevant from the perspective of
/// a thread attempting to acquire the lock, but internally the state uses `usize::MAX` as the
/// "exclusively locked" sentinel).
///
/// This mechanism gets us the following:
///
/// * Whether the lock has been acquired (shared or exclusive)
/// * Whether the lock is being exclusively acquired
/// * How many times the lock has been acquired
/// * Whether the acquisition(s) are exclusive or shared
///
/// Further implementation details, such as how we manage draining readers once an attempt to
/// exclusively acquire the lock occurs, are described below.
///
/// NOTE: This is a simple implementation, meant for use in no-std environments; there are much
/// more robust/performant implementations available when OS primitives can be used.
pub struct Spinlock {
    /// The state of the lock, primarily representing the acquisition count, but relying on
    /// the distinction between even and odd values to indicate whether or not exclusive access
    /// is being acquired.
    state: AtomicUsize,
    /// A counter used to wake a parked writer once the last shared lock is released during
    /// acquisition of an exclusive lock. The actual count is not acutally important, and
    /// simply wraps around on overflow, but what is important is that when the value changes,
    /// the writer will wake and resume attempting to acquire the exclusive lock.
    writer_wake_counter: AtomicUsize,
}

impl Default for Spinlock {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl Spinlock {
    #[cfg(not(loom))]
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            writer_wake_counter: AtomicUsize::new(0),
        }
    }

    #[cfg(loom)]
    pub fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            writer_wake_counter: AtomicUsize::new(0),
        }
    }
}

unsafe impl RawRwLock for Spinlock {
    #[cfg(loom)]
    const INIT: Spinlock = unimplemented!();

    #[cfg(not(loom))]
    // This is intentional on the part of the [RawRwLock] API, basically a hack to provide
    // initial values as static items.
    const INIT: Spinlock = Spinlock::new();

    type GuardMarker = lock_api::GuardSend;

    /// The operation invoked when calling `RwLock::read`, blocks the caller until acquired
    fn lock_shared(&self) {
        let mut s = self.state.load(Ordering::Relaxed);
        loop {
            // If the exclusive bit is unset, attempt to acquire a read lock
            if s & 1 == 0 {
                match self.state.compare_exchange_weak(
                    s,
                    s + 2,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    // Someone else beat us to the punch and acquired a lock
                    Err(e) => s = e,
                }
            }
            // If an exclusive lock is held/being acquired, loop until the lock state changes
            // at which point, try to acquire the lock again
            if s & 1 == 1 {
                loop {
                    let next = self.state.load(Ordering::Relaxed);
                    if s == next {
                        hint::spin_loop();
                        continue;
                    } else {
                        s = next;
                        break;
                    }
                }
            }
        }
    }

    /// The operation invoked when calling `RwLock::try_read`, returns whether or not the
    /// lock was acquired
    fn try_lock_shared(&self) -> bool {
        let s = self.state.load(Ordering::Relaxed);
        if s & 1 == 0 {
            self.state
                .compare_exchange_weak(s, s + 2, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        } else {
            false
        }
    }

    /// The operation invoked when dropping a `RwLockReadGuard`
    unsafe fn unlock_shared(&self) {
        if self.state.fetch_sub(2, Ordering::Release) == 3 {
            // The lock is being exclusively acquired, and we're the last shared acquisition
            // to be released, so wake the writer by incrementing the wake counter
            self.writer_wake_counter.fetch_add(1, Ordering::Release);
        }
    }

    /// The operation invoked when calling `RwLock::write`, blocks the caller until acquired
    fn lock_exclusive(&self) {
        let mut s = self.state.load(Ordering::Relaxed);
        loop {
            // Attempt to acquire the lock immediately, or complete acquistion of the lock
            // if we're continuing the loop after acquiring the exclusive bit. If another
            // thread acquired it first, we race to be the first thread to acquire it once
            // released, by busy looping here.
            if s <= 1 {
                match self.state.compare_exchange(
                    s,
                    usize::MAX,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(e) => {
                        s = e;
                        hint::spin_loop();
                        continue;
                    },
                }
            }

            // Only shared locks have been acquired, attempt to acquire the exclusive bit,
            // which will prevent further shared locks from being acquired. It does not
            // in and of itself grant us exclusive access however.
            if s & 1 == 0
                && let Err(e) =
                    self.state.compare_exchange(s, s + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                // The lock state has changed before we could acquire the exclusive bit,
                // update our view of the lock state and try again
                s = e;
                continue;
            }

            // We've acquired the exclusive bit, now we need to busy wait until all shared
            // acquisitions are released.
            let w = self.writer_wake_counter.load(Ordering::Acquire);
            s = self.state.load(Ordering::Relaxed);

            // "Park" the thread here (by busy looping), until the release of the last shared
            // lock, which is communicated to us by it incrementing the wake counter.
            if s >= 2 {
                while self.writer_wake_counter.load(Ordering::Acquire) == w {
                    hint::spin_loop();
                }
                s = self.state.load(Ordering::Relaxed);
            }

            // All shared locks have been released, go back to the top and try to complete
            // acquisition of exclusive access.
        }
    }

    /// The operation invoked when calling `RwLock::try_write`, returns whether or not the
    /// lock was acquired
    fn try_lock_exclusive(&self) -> bool {
        let s = self.state.load(Ordering::Relaxed);
        if s <= 1 {
            self.state
                .compare_exchange(s, usize::MAX, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        } else {
            false
        }
    }

    /// The operation invoked when dropping a `RwLockWriteGuard`
    unsafe fn unlock_exclusive(&self) {
        // Infallible, as we hold an exclusive lock
        //
        // Note the use of `Release` ordering here, which ensures any loads of the lock state
        // by other threads, are ordered after this store.
        self.state.store(0, Ordering::Release);
        // This fetch_add isn't important for signaling purposes, however it serves a key
        // purpose, in that it imposes a memory ordering on any loads of this field that
        // have an `Acquire` ordering, i.e. they will read the value stored here. Without
        // a `Release` store, loads/stores of this field could be reordered relative to
        // each other.
        self.writer_wake_counter.fetch_add(1, Ordering::Release);
    }
}

#[cfg(all(loom, test))]
mod test {
    use alloc::vec::Vec;

    use loom::{model::Builder, sync::Arc};

    use super::{RwLock, Spinlock};

    #[test]
    fn test_rwlock_loom() {
        let mut builder = Builder::default();
        builder.max_duration = Some(std::time::Duration::from_secs(60));
        builder.log = true;
        builder.check(|| {
            let raw_rwlock = Spinlock::new();
            let n = Arc::new(RwLock::from_raw(raw_rwlock, 0usize));
            let mut readers = Vec::new();
            let mut writers = Vec::new();

            let num_readers = 2;
            let num_writers = 2;
            let num_iterations = 2;

            // Readers should never observe a non-zero value
            for _ in 0..num_readers {
                let n0 = n.clone();
                let t = loom::thread::spawn(move || {
                    for _ in 0..num_iterations {
                        let guard = n0.read();
                        assert_eq!(*guard, 0);
                    }
                });

                readers.push(t);
            }

            // Writers should never observe a non-zero value once they've
            // acquired the lock, and should never observe a value > 1
            // while holding the lock
            for _ in 0..num_writers {
                let n0 = n.clone();
                let t = loom::thread::spawn(move || {
                    for _ in 0..num_iterations {
                        let mut guard = n0.write();
                        assert_eq!(*guard, 0);
                        *guard += 1;
                        assert_eq!(*guard, 1);
                        *guard -= 1;
                        assert_eq!(*guard, 0);
                    }
                });

                writers.push(t);
            }

            for t in readers {
                t.join().unwrap();
            }

            for t in writers {
                t.join().unwrap();
            }
        })
    }
}
