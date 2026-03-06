//! Blake3 STARK configuration factory.
//!
//! Uses native Blake3 for both the LMCS commitment scheme (via `ChainingHasher`)
//! and the Fiat-Shamir challenger.

use alloc::vec;

use miden_core::field::QuadFelt;
use miden_crypto::stark::{
    GenericStarkConfig,
    challenger::{HashChallenger, SerializingChallenger64},
    crypto::{CompressionFunctionFromHasher, p3_blake3::Blake3, p3_miden_stateful_hasher::ChainingHasher},
    lmcs::LmcsConfig,
};

use super::{Dft, PCS_PARAMS};
use crate::Felt;

/// Stateful hasher wrapping Blake3 for LMCS leaf hashing
type Sponge = ChainingHasher<Blake3>;

/// Compression function for Merkle tree internal nodes (Blake3, 32-byte digest)
type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;

/// LMCS commitment scheme using Blake3
type LmcsType = LmcsConfig<Felt, u8, Sponge, Compress, 32, 32>;

/// Challenger for Fiat-Shamir using Blake3
type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Blake3, 32>>;

/// Complete STARK configuration type for Blake3_256.
pub type Blake3Config = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates a Blake3_256-based STARK configuration.
pub fn create_blake3_256_config() -> Blake3Config {
    let sponge = Sponge::new(Blake3);
    let compress = Compress::new(Blake3);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::from_hasher(vec![], Blake3);

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}
