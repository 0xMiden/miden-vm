//! Symbolic circuit construction for the authored VM relation.

mod multi_air;
mod recursive;

pub use miden_ace_codegen::{CapturedAir, CompiledRelation, LayoutKind};
pub use multi_air::build_canonical_multi_air_ace_circuit;
pub use recursive::{build_recursive_verifier_ace_circuit, recursive_verifier_ace_config};
