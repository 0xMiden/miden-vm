//! Mock precompiles used to exercise the deferred framework.
//!
//! They cover single-chunk values, join nodes, multi-chunk data payloads, predicates, and compound
//! canonicals without depending on production cryptographic implementations.

pub mod group;
pub mod hash;
pub mod sig;
pub mod uint;

pub use group::Group;
pub use hash::Hash;
pub use sig::Sig;
pub use uint::Uint;

use crate::deferred::PrecompileRegistry;

/// Builds a registry with every mock precompile installed.
///
/// This is the default fixture registry for framework tests, which exercise the deferred framework
/// rather than any single precompile. Tests that need an empty or narrow registry build one
/// directly with [`PrecompileRegistry::with_precompile`].
pub fn mock_precompile_registry() -> PrecompileRegistry {
    PrecompileRegistry::default()
        .with_precompile(Uint)
        .with_precompile(Hash)
        .with_precompile(Sig)
        .with_precompile(Group)
}
