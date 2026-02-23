//! Constraint tagging helpers for stable numeric IDs.
//!
//! This module dispatches to the full tagging implementation in test/`testing` builds
//! and a no-op fallback in production/no-std builds.

pub mod manifest;

#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod enabled;
#[cfg(not(all(any(test, feature = "testing"), feature = "std")))]
mod fallback;

#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod fixtures;
#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod ood_eval;
#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod state;
#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod tagged_builder;

#[cfg(all(any(test, feature = "testing"), feature = "std"))]
pub use enabled::*;
#[cfg(not(all(any(test, feature = "testing"), feature = "std")))]
pub use fallback::*;
