//! Poseidon2 STARK configuration factory.

use miden_core::field::QuadFelt;
use miden_crypto::{
    hash::poseidon2::Poseidon2Permutation256,
    stark::{
        GenericStarkConfig,
        challenger::DuplexChallenger,
        crypto::{StatefulSponge, TruncatedPermutation},
        field::Field,
        lmcs::LmcsConfig,
    },
};

use super::{Dft, PCS_PARAMS};
use crate::Felt;

const WIDTH: usize = 12;
const RATE: usize = 8;
const DIGEST: usize = 4;

type Perm = Poseidon2Permutation256;
type PackedFelt = <Felt as Field>::Packing;
type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;
type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;
type LmcsType = LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;
type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

pub type Poseidon2Config = GenericStarkConfig<Felt, QuadFelt, LmcsType, Dft, Challenger>;

/// Creates a Poseidon2-based STARK configuration.
pub fn create_poseidon2_config() -> Poseidon2Config {
    let perm = Poseidon2Permutation256;
    let sponge = Sponge::new(perm);
    let compress = Compress::new(perm);
    let lmcs = LmcsType::new(sponge, compress);
    let dft = Dft::default();
    let challenger = Challenger::new(perm);

    GenericStarkConfig::new(PCS_PARAMS, lmcs, dft, challenger)
}
