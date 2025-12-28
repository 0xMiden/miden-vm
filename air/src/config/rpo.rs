//! RPO STARK configuration factory.
//!
//! This module provides a STARK configuration using the Rescue Prime Optimized (RPO)
//! hash function, which is Miden's native algebraic hash function.

use miden_crypto::{
    field::BinomialExtensionField,
    hash::rpo::{RpoChallenger, RpoCompression, RpoHasher, RpoPermutation256},
    stark::StarkConfig,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{FriParameters, TwoAdicFriPcs};

use crate::Felt;

/// Challenge field type for RPO config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// RPO hasher (sponge-based)
type Hash = RpoHasher;

/// Compression function using RPO (2-to-1 compression)
type Compress = RpoCompression;

/// Merkle tree commitment scheme over base field using RPO
/// Note: RPO uses Felt (field elements) for digests, not u8 (bytes)
type ValMmcs = MerkleTreeMmcs<Felt, Felt, Hash, Compress, 4>;

/// Merkle tree commitment scheme over extension field using RPO
type ChallengeMmcs = ExtensionMmcs<Felt, Challenge, ValMmcs>;

/// DFT implementation for polynomial operations
type Dft = Radix2DitParallel<Felt>;

/// FRI-based PCS using RPO
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs, ChallengeMmcs>;

/// Challenger for Fiat-Shamir using RPO
type Challenger = RpoChallenger<Felt>;

/// Complete STARK configuration using RPO
pub type StarkConfigRpo = StarkConfig<FriPcs, Challenge, Challenger>;

/// Creates an RPO-based STARK configuration.
///
/// This configuration uses:
/// - RPO (Rescue Prime Optimized) hash function for Merkle trees and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1) - fold by 2 each round
///
/// # Advantages of RPO over Blake3
///
/// - **Native to Miden VM**: RPO is an algebraic hash function that can be efficiently verified
///   within the Miden VM itself, enabling recursive proof verification.
/// - **STARK-friendly**: Being algebraic (defined over the same field as the trace), RPO
///   constraints are more efficient to represent and verify.
/// - **Smaller proof size**: RPO's algebraic nature typically results in more compact Merkle
///   authentication paths.
///
/// # Returns
///
/// A `StarkConfig` instance configured for RPO-based proving.
pub fn create_rpo_config() -> StarkConfigRpo {
    let perm = RpoPermutation256;
    let hash = RpoHasher::new(perm);
    let compress = RpoCompression::new(perm);

    let val_mmcs = ValMmcs::new(hash, compress);
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
    let challenger = RpoChallenger::new(perm);

    StarkConfig::new(pcs, challenger)
}
