//! Reference precompiles used to exercise the deferred framework.
//!
//! They cover value leaves, join nodes, chunk bodies, predicates, and compound canonicals without
//! depending on production cryptographic implementations.

pub mod group;
pub mod hash;
pub mod sig;
pub mod uint;

pub use group::Group;
pub use hash::Hash;
pub use sig::Sig;
pub use uint::Uint;
