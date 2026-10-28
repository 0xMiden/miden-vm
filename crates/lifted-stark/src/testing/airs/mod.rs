//! Example AIRs wrapped for the lifted STARK prover.
//!
//! Each module adapts an upstream Plonky3 AIR into a `LiftedAir` so it can be proven
//! and verified with the lifted STARK protocol.

pub mod blake3;
pub mod keccak;
pub mod miden;
pub mod poseidon2;
