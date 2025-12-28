//! RPX STARK configuration factory.
//!
//! This module provides a STARK configuration using the Rescue Prime eXtension (RPX)
//! hash function, which is Miden's native algebraic hash function with extension field rounds.

use miden_crypto::{
    field::BinomialExtensionField,
    hash::rpx::{RpxChallenger, RpxCompression, RpxHasher, RpxPermutation256},
    stark::StarkConfig,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{FriParameters, TwoAdicFriPcs};

use crate::Felt;

/// Challenge field type for RPX config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// RPX hasher (sponge-based)
type Hash = RpxHasher;

/// Compression function using RPX (2-to-1 compression)
type Compress = RpxCompression;

/// Merkle tree commitment scheme over base field using RPX
/// Note: RPX uses Felt (field elements) for digests, not u8 (bytes)
type ValMmcs = MerkleTreeMmcs<Felt, Felt, Hash, Compress, 4>;

/// Merkle tree commitment scheme over extension field using RPX
type ChallengeMmcs = ExtensionMmcs<Felt, Challenge, ValMmcs>;

/// DFT implementation for polynomial operations
type Dft = Radix2DitParallel<Felt>;

/// FRI-based PCS using RPX
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs, ChallengeMmcs>;

/// Challenger for Fiat-Shamir using RPX
type Challenger = RpxChallenger<Felt>;

/// Complete STARK configuration using RPX
pub type StarkConfigRpx = StarkConfig<FriPcs, Challenge, Challenger>;

/// Creates an RPX-based STARK configuration.
///
/// This configuration uses:
/// - RPX (Rescue Prime eXtension) hash function for Merkle trees and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1) - fold by 2 each round
///
/// # Advantages of RPX over RPO
///
/// - **Enhanced security**: RPX uses extension field rounds (E-rounds) that provide additional
///   algebraic structure and resistance to certain attacks.
/// - **Native to Miden VM**: Like RPO, RPX is an algebraic hash function that can be efficiently
///   verified within the Miden VM for recursive proof verification.
/// - **STARK-friendly**: The extension field operations are optimized for STARK circuits, providing
///   efficient constraint representation.
/// - **128-bit security**: Targets the same security level as RPO with improved cryptographic
///   properties.
///
/// # Returns
///
/// A `StarkConfig` instance configured for RPX-based proving.
pub fn create_rpx_config() -> StarkConfigRpx {
    let perm = RpxPermutation256;
    let hash = RpxHasher::new(perm);
    let compress = RpxCompression::new(perm);

    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

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

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);
    let challenger = RpxChallenger::new(perm);

    StarkConfig::new(pcs, challenger)
}
