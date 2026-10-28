//! Miden VM relation proving, native verification, and recursive advice.
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod debug;
pub mod memory;
#[cfg(feature = "prover")]
pub mod prover;
pub mod recursive;
pub mod security;
pub mod setup;
pub mod verifier;

pub use miden_air_definitions::vm::VmTrace;
pub use miden_core::{
    Word,
    advice::AdviceInputs,
    program::ExecutionClaim,
    proof::{ExecutionProof, HashFunction, VmProof},
};
