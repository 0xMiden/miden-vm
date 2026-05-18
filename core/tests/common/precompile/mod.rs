//! Reference precompile implementations used by the `precompile_*` integration tests.
//!
//! - [`uint`] — `Uint`: 256-bit wrapping integer arithmetic.
//! - [`group`] — `Group`: compound-canonical mock group over `Uint` (mid-`reduce` minting).
//! - [`hash`] — `Hash`: chunk-bodied preimage → digest-leaf app.
//! - [`sig`] — `Sig`: single chunk-bodied predicate app.

pub mod group;
pub mod hash;
pub mod sig;
pub mod uint;

pub use group::Group;
pub use hash::Hash;
pub use sig::Sig;
pub use uint::Uint;
