//! Keccak STARK configuration factory.

use alloc::vec;

use miden_core::field::QuadFelt;
use miden_crypto::{
    hash::keccak::Keccak256Hash,
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

type Sponge = ChainingHasher<Keccak256Hash>;
type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
type LmcsType = LmcsConfig<Felt, u8, Sponge, Compress, 32, 32>;
type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Keccak256Hash, 32>>;

pub type KeccakConfig = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates a Keccak-based STARK configuration.
pub fn create_keccak_config() -> KeccakConfig {
    let sponge = Sponge::new(Keccak256Hash {});
    let compress = Compress::new(Keccak256Hash {});
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::from_hasher(vec![], Keccak256Hash {});

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}
