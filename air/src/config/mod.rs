//! STARK configuration factories for different hash functions.
//!
//! This module provides factory functions that create [`StarkConfig`] instances
//! for different hash functions (Blake3, Keccak, RPO256, Poseidon2, RPX256). Each config
//! bundles the PCS parameters, LMCS commitment scheme, and challenger for proving
//! and verification.

use miden_core::Felt;
use miden_crypto::stark::fri::{DeepParams, FriFold, FriParams, PcsParams};

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

// SHARED TYPES
// ================================================================================================

/// DFT implementation for polynomial operations.
pub type Dft = miden_crypto::stark::dft::Radix2DitParallel<Felt>;

/// PCS parameters shared by all hash function configurations.
///
/// - FRI with 8x blowup (log_blowup = 3)
/// - Arity-4 folding
/// - Final polynomial degree 2^7 = 128
/// - 16 bits of folding proof-of-work
/// - 27 query repetitions
pub const PCS_PARAMS: PcsParams = PcsParams {
    fri: FriParams {
        log_blowup: 3,
        fold: FriFold::ARITY_4,
        log_final_degree: 7,
        folding_pow_bits: 16,
    },
    deep: DeepParams { deep_pow_bits: 0 },
    num_queries: 27,
    query_pow_bits: 0,
};
