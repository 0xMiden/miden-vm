//! Blake3 STARK configuration factory.
//!
//! Uses native Blake3 for both the LMCS commitment scheme (via `ChainingHasher`)
//! and the Fiat-Shamir challenger.

use alloc::vec;

use miden_core::field::QuadFelt;
use miden_crypto::{
    hash::blake::Blake3Hasher,
    stark::{
        GenericStarkConfig,
        challenger::{HashChallenger, SerializingChallenger64},
        hasher::ChainingHasher,
        lmcs::LmcsConfig,
        symmetric::CompressionFunctionFromHasher,
    },
};

use super::{Dft, PCS_PARAMS};
use crate::Felt;

/// Stateful hasher wrapping Blake3 for LMCS leaf hashing
type Sponge = ChainingHasher<Blake3Hasher>;

/// Compression function for Merkle tree internal nodes (Blake3, 32-byte digest)
type Compress = CompressionFunctionFromHasher<Blake3Hasher, 2, 32>;

/// LMCS commitment scheme using Blake3
type LmcsType = LmcsConfig<Felt, u8, Sponge, Compress, 32, 32>;

/// Challenger for Fiat-Shamir using Blake3
type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Blake3Hasher, 32>>;

/// Complete STARK configuration type for Blake3_256.
pub type Blake3Config = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates a Blake3_256-based STARK configuration.
pub fn create_blake3_256_config() -> Blake3Config {
    let sponge = Sponge::new(Blake3Hasher);
    let compress = Compress::new(Blake3Hasher);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::from_hasher(vec![], Blake3Hasher);

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}
