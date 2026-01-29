#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod once_lock;
pub mod racy_lock;
pub mod rw_lock;

#[cfg(feature = "std")]
pub use std::sync::LazyLock;

pub use once_lock::OnceLockCompat;
#[cfg(feature = "std")]
pub use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(not(feature = "std"))]
pub use racy_lock::RacyLock as LazyLock;
#[cfg(not(feature = "std"))]
pub use rw_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
