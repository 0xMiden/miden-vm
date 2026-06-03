//! Reference precompiles used to exercise the deferred framework.
//!
//! They cover values (`Data(1)`), join nodes, multi-chunk data, predicates, and compound canonicals
//! without depending on production cryptographic implementations.

pub mod group;
pub mod hash;
pub mod sig;
pub mod uint;

pub use group::Group;
pub use hash::Hash;
pub use sig::Sig;
pub use uint::Uint;
