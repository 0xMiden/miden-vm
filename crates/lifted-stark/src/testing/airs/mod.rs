//! Example AIRs wrapped for the lifted STARK prover.
//!
//! Each module adapts an upstream Plonky3 AIR into a `LiftedAir` so it can be proven
//! and verified with the lifted STARK protocol.

#[cfg(feature = "testing")]
pub mod blake3;
#[cfg(feature = "testing")]
pub mod keccak;
pub mod miden;
#[cfg(feature = "testing")]
pub mod poseidon2;
