// Blake3 prover using p3-uni-stark APIs
//
// This implementation replaces the manual STARK protocol with Plonky3's high-level
// p3_uni_stark::prove() function, reducing code from 215 lines to ~70 lines.

use alloc::vec;
use alloc::vec::Vec;

use miden_air::{Felt, ProcessorAir};
use miden_processor::ExecutionTrace;
use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

use super::utils::to_row_major;

type Challenge = BinomialExtensionField<Felt, 2>;
type H = Blake3;

type FieldHash = SerializingHasher<H>;
type Compress<H> = CompressionFunctionFromHasher<H, 2, 32>;
type ValMmcs<H> = MerkleTreeMmcs<Felt, u8, FieldHash, Compress<H>, 32>;
type ChallengeMmcs<H> = ExtensionMmcs<Felt, Challenge, ValMmcs<H>>;
type FriPcs = TwoAdicFriPcs<Felt, Dft, ValMmcs<H>, ChallengeMmcs<H>>;
type Dft = Radix2DitParallel<Felt>;
type Challenger<H> = SerializingChallenger64<Felt, HashChallenger<u8, H, 32>>;
type StarkConfigBlake = StarkConfig<FriPcs, Challenge, Challenger<H>>;

/// Prove execution using Blake3 hash function and p3-uni-stark APIs.
///
/// This replaces the manual 215-line STARK protocol implementation with a single
/// call to p3_uni_stark::prove(), which handles all phases automatically:
/// - Phase 1: Commit main trace
/// - Phase 2: Sample challenges & commit aux trace (if applicable)
/// - Phase 3: Compute and commit quotient polynomials
/// - Phase 4: Open at evaluation point
pub fn prove_blake(trace: ExecutionTrace) -> Vec<u8> {
    let air = ProcessorAir;
    let public_values = vec![];

    // Convert trace from column-major to row-major format
    let trace_row_major = to_row_major(&trace);

    // Generate Blake3 configuration
    let config = generate_blake_config();

    // Prove using p3-uni-stark - this single call replaces 150+ lines of manual protocol
    let proof = p3_uni_stark::prove(&config, &air, &trace_row_major, &public_values);

    // Serialize proof to bytes
    bincode::serialize(&proof).expect("failed to serialize proof")
}

/// Generate Blake3 STARK configuration.
///
/// Uses Blake3 hash function for Merkle tree commitments with fixed FRI parameters
/// tuned for production use (27 queries, 96-bit security).
pub fn generate_blake_config() -> StarkConfigBlake {
    let field_hash = FieldHash::new(H {});
    let compress = Compress::new(H {});

    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    // Fixed FRI parameters for production use
    // log_blowup: 3 (8x blowup factor)
    // log_final_poly_len: 7 (128 coefficients in final polynomial)
    // num_queries: 27 (provides ~96 bits of security)
    let fri_config = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 7,
        num_queries: 27,
        proof_of_work_bits: 16,
        log_folding_factor: 1,
        mmcs: challenge_mmcs,
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);

    let challenger = Challenger::from_hasher(vec![], H {});

    StarkConfigBlake::new(pcs, challenger)
}
