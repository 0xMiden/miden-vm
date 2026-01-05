//! Poseidon2 STARK configuration factory.
//!
//! This module provides a STARK configuration using the Poseidon2 hash function,
//! which is an algebraic hash function designed for STARK-friendly operations.

use miden_crypto::{
    field::BinomialExtensionField,
    hash::poseidon2::{
        Poseidon2Challenger, Poseidon2Compression, Poseidon2Hasher, Poseidon2Permutation256,
    },
    stark::StarkConfig,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{FriParameters, TwoAdicFriPcs};

use crate::Felt;

/// Challenge field type for Poseidon2 config (degree-2 extension of Felt)
pub type Challenge = BinomialExtensionField<Felt, 2>;

/// Poseidon2 hasher (sponge-based)
type Hash = Poseidon2Hasher;

/// Compression function using Poseidon2 (2-to-1 compression)
type Compress = Poseidon2Compression;

/// Merkle tree commitment scheme over base field using Poseidon2
/// Note: Poseidon2 uses Felt (field elements) for digests, not u8 (bytes)
type ValMmcs = MerkleTreeMmcs<Felt, Felt, Hash, Compress, 4>;

/// Merkle tree commitment scheme over extension field using Poseidon2
type ChallengeMmcs = ExtensionMmcs<Felt, Challenge, ValMmcs>;

/// DFT implementation for polynomial operations
type Dft = Radix2DitParallel<Felt>;

/// FRI-based PCS using Poseidon2
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs, ChallengeMmcs>;

/// Challenger for Fiat-Shamir using Poseidon2
type Challenger = Poseidon2Challenger<Felt>;

/// Complete STARK configuration using Poseidon2
pub type StarkConfigPoseidon2 = StarkConfig<FriPcs, Challenge, Challenger>;

/// Creates a Poseidon2-based STARK configuration.
///
/// This configuration uses:
/// - Poseidon2 hash function for Merkle trees and Fiat-Shamir
/// - FRI with 8x blowup (log_blowup = 3)
/// - 27 query repetitions
/// - 16 bits of proof-of-work
/// - Binary folding (log_folding_factor = 1) - fold by 2 each round
///
/// # Advantages of Poseidon2
///
/// - **STARK-friendly**: Poseidon2 is an algebraic hash function optimized for STARK circuits, with
///   efficient constraint representation.
/// - **Improved performance**: Compared to Poseidon (original), Poseidon2 offers better performance
///   with similar security guarantees.
/// - **Native to field arithmetic**: Being algebraic, Poseidon2 constraints are more efficient to
///   verify within the VM.
///
/// # Returns
///
/// A `StarkConfig` instance configured for Poseidon2-based proving.
pub fn create_poseidon2_config() -> StarkConfigPoseidon2 {
    let perm = Poseidon2Permutation256;
    let hash = Poseidon2Hasher::new(perm);
    let compress = Poseidon2Compression::new(perm);

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
    let challenger = Poseidon2Challenger::new(perm);

    StarkConfig::new(pcs, challenger)
}
