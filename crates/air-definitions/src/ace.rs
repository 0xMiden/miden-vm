//! ACE circuit integration for the Miden multi-AIR proof.
//!
//! Runtime circuit metadata is available without compiler tooling. Canonical circuit construction
//! and recursive-verifier circuit configuration are available in `crate::compiler::vm` when the
//! `compiler` feature is enabled.
//!
//! The cross-AIR LogUp boundary identity is checked outside the circuit as
//! `sum_i(n_i * sigma_prime_i) + c_boundary = 0`, where `sigma_prime_i` is AIR `i`'s
//! normalized committed LogUp sum and `n_i` is its trace length.

// Runtime circuit representation remains available without compiler tooling.
pub use miden_ace_codegen::RecursiveAceCircuit;
