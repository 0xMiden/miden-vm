//! Keccak STARK configuration factory.

use alloc::vec;

use miden_crypto::{
    field::BinomialExtensionField,
    stark::{
        StarkConfig,
        challenger::{HashChallenger, SerializingChallenger64},
        symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher},
    },
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{FriParameters, TwoAdicFriPcs};

use crate::Felt;

/// Challenge field type for Keccak config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// Standard Keccak256 for byte hashing (used by challenger)
pub type ByteHash = Keccak256Hash;

/// Keccak optimized for u64 field elements (padding-free sponge)
pub type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;

/// Field element serializing hasher using Keccak
pub type FieldHash = SerializingHasher<U64Hash>;

/// Compression function derived from Keccak hasher
pub type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;

/// Merkle tree commitment scheme over base field using Keccak
pub type ValMmcs = MerkleTreeMmcs<
    [Felt; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    4,
>;

/// Merkle tree commitment scheme over extension field
pub type ChallengeMmcs = ExtensionMmcs<Felt, Challenge, ValMmcs>;

/// DFT implementation for polynomial operations
pub type Dft = Radix2DitParallel<Felt>;

/// FRI-based PCS using Keccak
pub type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs, ChallengeMmcs>;

/// Challenger for Fiat-Shamir using Keccak256
pub type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, ByteHash, 32>>;

/// Complete STARK configuration using Keccak
pub type StarkConfigKeccak = StarkConfig<FriPcs, Challenge, Challenger>;

/// Creates a Keccak-based STARK configuration.
///
/// This configuration uses:
/// - Keccak256 for the Fiat-Shamir challenger
/// - KeccakF permutation for field element hashing in Merkle trees
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1)
///
/// # Returns
///
/// A `StarkConfig` instance configured for Keccak-based proving.
pub fn create_keccak_config() -> StarkConfigKeccak {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let compress = MyCompress::new(u64_hash);

    let field_hash = FieldHash::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let fri_config = FriParameters {
        log_blowup: 3,          // 8x blowup factor
        log_final_poly_len: 7,  // Final polynomial degree 2^7 = 128
        num_queries: 27,        // Number of FRI query repetitions
        proof_of_work_bits: 16, // Grinding parameter
        mmcs: challenge_mmcs,
        log_folding_factor: 1, // Binary folding
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    StarkConfig::new(pcs, challenger)
}
