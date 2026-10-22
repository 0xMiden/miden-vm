#![no_std]

//! Native proving, verification, setup, and recursive advice for the precompile relation.

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, PrecompileProof, StarkProof},
};
pub use miden_stark::security::ProofSecurityParameters;

#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "std")]
pub mod recursive;
pub mod setup;
pub mod verifier;
