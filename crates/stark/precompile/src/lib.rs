#![no_std]

//! Native proving, verification, and recursive advice for the precompile relation.

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_air::precompiles::security::ProofSecurityParameters;
pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, PrecompileProof, StarkProof},
};

#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "std")]
pub mod recursive;
pub mod verifier;
