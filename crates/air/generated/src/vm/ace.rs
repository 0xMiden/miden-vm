//! Production recursive ACE access; compilation is source tooling only.
pub use miden_ace::RecursiveAceCircuit;

pub use super::artifacts::recursive_circuit as build_recursive_verifier_ace_circuit;
#[cfg(feature = "std")]
pub use super::artifacts::shared_recursive_circuit;
