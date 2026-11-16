#![no_std]

//! Native proving, verification, setup, and recursive advice for the precompile relation.

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "std")]
pub mod recursive;
pub mod setup;
pub mod verifier;
