#![no_std]

#[macro_use]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

/// Authored precompile equations, schema, fixed data, and statement semantics.
pub mod precompile;
/// Authored VM equations, schema, fixed data, and statement semantics.
pub mod vm;

// Transitional schema/trait paths keep processor migration mechanical. The ordinary relation
// types live under `vm` and `precompile`; no source evaluator imports generated AIR.
pub use miden_stark::air::MultiAir;
pub(crate) use vm::constraints;
pub use vm::{Air as MidenAir, MultiAir as MidenMultiAir, *};

#[cfg(feature = "tooling")]
pub mod codegen;

/// Shared Eidos equation, layout, and writer primitives, with relation-specific adapters
/// above.
pub use vm::constraints::eidos_compression as eidos;
