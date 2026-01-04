//! STARK configuration factories for different hash functions.
//!
//! This module provides factory functions that create `StarkConfig` instances
//! for different hash functions (Blake3, Keccak, RPO256, Poseidon2). Each config
//! specifies the PCS (Polynomial Commitment Scheme), FRI parameters, and challenger
//! for proving and verification.

mod blake3;
mod keccak;
mod poseidon2;
mod rpo;
mod rpx;

pub use blake3::create_blake3_256_config;
pub use keccak::create_keccak_config;
pub use poseidon2::create_poseidon2_config;
pub use rpo::create_rpo_config;
pub use rpx::create_rpx_config;
