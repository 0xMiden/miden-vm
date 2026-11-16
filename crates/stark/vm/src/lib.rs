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
