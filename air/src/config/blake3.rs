//! Blake3 STARK configuration factory.
//!
//! Currently only supports Blake3_256 (256-bit / 32-byte output).
//!
//! TODO: Blake3_192 support requires adding CryptographicHasher<u8, [u8; 24]> trait
//! implementation to p3_blake3::Blake3. Create an issue in 0xMiden/Plonky3 to add
//! support for configurable output sizes (24-byte and 32-byte variants).

use alloc::vec;

use miden_crypto::{
    field::BinomialExtensionField,
    stark::{
        StarkConfig,
        challenger::{HashChallenger, SerializingChallenger64},
        symmetric::{CompressionFunctionFromHasher, SerializingHasher},
    },
};
use p3_blake3::Blake3;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{FriParameters, TwoAdicFriPcs};

use crate::Felt;

/// Challenge field type for Blake3 config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// Blake3 hasher
type H = Blake3;

/// Field element serializing hasher using Blake3
type FieldHash = SerializingHasher<H>;

/// DFT implementation for polynomial operations
type Dft = Radix2DitParallel<Felt>;

// ================================================================================================
// BLAKE3_256 (32-byte digest)
// ================================================================================================

/// Compression function for Blake3_256 (32-byte output)
type Compress256 = CompressionFunctionFromHasher<H, 2, 32>;

/// Merkle tree commitment scheme over base field (Blake3_256)
type ValMmcs256 = MerkleTreeMmcs<Felt, u8, FieldHash, Compress256, 32>;

/// Merkle tree commitment scheme over extension field (Blake3_256)
type ChallengeMmcs256 = ExtensionMmcs<Felt, Challenge, ValMmcs256>;

/// FRI-based PCS using Blake3_256
type FriPcs256 = TwoAdicFriPcs<Felt, Dft, ValMmcs256, ChallengeMmcs256>;

/// Challenger for Fiat-Shamir using Blake3_256
type Challenger256 = SerializingChallenger64<Felt, HashChallenger<u8, H, 32>>;

/// Complete STARK configuration using Blake3_256
pub type StarkConfigBlake3_256 = StarkConfig<FriPcs256, Challenge, Challenger256>;

/// Creates a Blake3_256-based STARK configuration (256-bit / 32-byte output).
///
/// This configuration uses:
/// - Blake3 hash function with 256-bit output for Merkle trees and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1)
///
/// # Returns
///
/// A `StarkConfig` instance configured for Blake3_256-based proving.
pub fn create_blake3_256_config() -> StarkConfigBlake3_256 {
    let field_hash = FieldHash::new(H {});
    let compress = Compress256::new(H {});

    let val_mmcs = ValMmcs256::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs256::new(val_mmcs.clone());

    let dft = Dft::default();

    let fri_config = FriParameters {
        log_blowup: 3,          // 8x blowup factor
        log_final_poly_len: 7,  // Final polynomial degree 2^7 = 128
        num_queries: 27,        // Number of FRI query repetitions
        proof_of_work_bits: 16, // Grinding parameter
        mmcs: challenge_mmcs,
        log_folding_factor: 1, /* Binary folding
                                * NOTE:  (log_folding_factor: 3) causes
                                * RootMismatch errors
                                * in verification. This appears to be a bug in the
                                * 0xMiden/Plonky3 fork. */
    };

    let pcs = FriPcs256::new(dft, val_mmcs, fri_config);
    let challenger = Challenger256::from_hasher(vec![], H {});

    StarkConfig::new(pcs, challenger)
}
