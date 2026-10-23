//! ACE circuit integration for the Miden multi-AIR proof.
//!
//! Runtime circuit metadata is available without compiler tooling. Enabling `compiler` also
//! exposes canonical multi-AIR circuit construction and recursive-verifier circuit configuration.
//!
//! The cross-AIR LogUp boundary identity is checked outside the circuit as
//! `sum_i(n_i * sigma_prime_i) + c_boundary = 0`, where `sigma_prime_i` is AIR `i`'s
//! normalized committed LogUp sum and `n_i` is its trace length.

// Runtime circuit representation remains available without compiler tooling.
pub use miden_ace_codegen::RecursiveAceCircuit;

#[cfg(feature = "compiler")]
mod compiler;
#[cfg(feature = "compiler")]
pub use compiler::{
    CapturedAir, CompiledRelation, LayoutKind, build_canonical_multi_air_ace_circuit,
    build_recursive_verifier_ace_circuit, recursive_verifier_ace_config,
};
