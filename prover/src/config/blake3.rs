//! Blake3 STARK configuration factory.

use alloc::vec;

use miden_air::Felt;
use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

/// Challenge field type for Blake3 config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// Blake3 hasher
type H = Blake3;

/// Field element serializing hasher using Blake3
type FieldHash = SerializingHasher<H>;

/// Compression function derived from Blake3 hasher
type Compress<H> = CompressionFunctionFromHasher<H, 2, 32>;

/// Merkle tree commitment scheme over base field
type ValMmcs<H> = MerkleTreeMmcs<Felt, u8, FieldHash, Compress<H>, 32>;

/// Merkle tree commitment scheme over extension field
type ChallengeMmcs<H> = ExtensionMmcs<Felt, Challenge, ValMmcs<H>>;

/// DFT implementation for polynomial operations
type Dft = Radix2DitParallel<Felt>;

/// FRI-based PCS using Blake3
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs<H>, ChallengeMmcs<H>>;

/// Challenger for Fiat-Shamir using Blake3
type Challenger<H> = SerializingChallenger64<Felt, HashChallenger<u8, H, 32>>;

/// Complete STARK configuration using Blake3
pub type StarkConfigBlake3 = StarkConfig<FriPcs, Challenge, Challenger<H>>;

/// Creates a Blake3-based STARK configuration.
///
/// This configuration uses:
/// - Blake3 hash function for Merkle trees and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions for ~100 bits of security
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1)
///
/// # Returns
///
/// A `StarkConfig` instance configured for Blake3-based proving.
pub fn create_blake3_config() -> StarkConfigBlake3 {
    let field_hash = FieldHash::new(H {});
    let compress = Compress::new(H {});

    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    let fri_config = FriParameters {
        log_blowup: 3,          // 8x blowup factor
        log_final_poly_len: 7,  // Final polynomial degree 2^7 = 128
        num_queries: 27,        // Number of FRI query repetitions (~100 bits security)
        proof_of_work_bits: 16, // Grinding parameter for extra security
        mmcs: challenge_mmcs,
        log_folding_factor: 1, // Binary folding (fold by 2 each round)
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);
    let challenger = Challenger::from_hasher(vec![], H {});

    StarkConfig::new(pcs, challenger)
}
