//! Reference precompile implementations exercising the [`crate::deferred`] public surface.
//!
//! - [`uint`] — `Uint`: 256-bit wrapping integer arithmetic.
//! - [`group`] — `Group`: compound-canonical mock group over `Uint` (mid-`reduce` minting).
//! - [`hash`] — `Hash`: chunk-bodied preimage → digest-leaf precompile.
//! - [`sig`] — `Sig`: single chunk-bodied predicate precompile.

pub mod group;
pub mod hash;
pub mod sig;
pub mod uint;

pub use group::Group;
pub use hash::Hash;
pub use sig::Sig;
pub use uint::Uint;
