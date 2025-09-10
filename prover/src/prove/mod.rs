
use air::Felt;
use miden_crypto::{BinomialExtensionField, hash::rpo::RpoPermutation256};
use p3_blake3::Blake3;
use p3_challenger::{
    DuplexChallenger, HashChallenger,
    SerializingChallenger64,
};
use p3_commit::ExtensionMmcs;use p3_dft::Radix2DitParallel;

use p3_fri::TwoAdicFriPcs;

use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher64, TruncatedPermutation,
};
use p3_uni_stark::{
     StarkConfig,
};


mod utils;
mod types;
mod blake;
pub use rpo::prove_rpo;
pub use blake::prove_blake;
mod rpo;

// Types specific to proving configurations are now defined inside their respective modules.
type StarkConfigRpo = StarkConfig<
    TwoAdicFriPcs<
        Felt,
        Radix2DitParallel<Felt>,
        MerkleTreeMmcs<
            Felt,
            Felt,
            PaddingFreeSponge<RpoPermutation256, 12, 8, 4>,
            TruncatedPermutation<RpoPermutation256, 2, 4, 12>,
            4,
        >,
        ExtensionMmcs<
            Felt,
            BinomialExtensionField<Felt, 2>,
            MerkleTreeMmcs<
                Felt,
                Felt,
                PaddingFreeSponge<RpoPermutation256, 12, 8, 4>,
                TruncatedPermutation<RpoPermutation256, 2, 4, 12>,
                4,
            >,
        >,
    >,
    BinomialExtensionField<Felt, 2>,
    DuplexChallenger<Felt, RpoPermutation256, 12, 8>,
>;

// Types specific to proving configurations are now defined inside their respective modules.
type StarkConfigBlake = StarkConfig<
    TwoAdicFriPcs<
        Felt,
        Radix2DitParallel<Felt>,
        MerkleTreeMmcs<
            Felt,
            u8,
            SerializingHasher64<Blake3>,
            CompressionFunctionFromHasher<Blake3, 2, 32>,
            32,
        >,
        ExtensionMmcs<
            Felt,
            BinomialExtensionField<Felt, 2>,
            MerkleTreeMmcs<
                Felt,
                u8,
                SerializingHasher64<Blake3>,
                CompressionFunctionFromHasher<Blake3, 2, 32>,
                32,
            >,
        >,
    >,
    BinomialExtensionField<Felt, 2>,
    SerializingChallenger64<Felt, HashChallenger<u8, Blake3, 32>>,
>;
