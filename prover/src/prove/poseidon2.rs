// Poseidon2 prover using p3-uni-stark APIs
//
// This implementation replaces the manual STARK protocol with Plonky3's high-level
// p3_uni_stark::prove() function, reducing code from 200+ lines to ~30 lines.

use alloc::{vec, vec::Vec};

use miden_air::ProcessorAir;
use miden_processor::ExecutionTrace;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use p3_util::{log2_ceil_usize, log2_strict_usize};
use rand::Rng;

use super::utils::to_row_major;

// Type aliases for Poseidon2 configuration
type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;

// Poseidon2 configuration (16-width permutation)
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 22;

type Perm = Poseidon2Goldilocks<WIDTH>;
type MyHash = PaddingFreeSponge<Perm, WIDTH, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, WIDTH>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Challenger = DuplexChallenger<Val, Perm, WIDTH, 8>;
type StarkConfigPoseidon = StarkConfig<FriPcs, Challenge, Challenger>;

/// Prove execution using Poseidon2 hash function and p3-uni-stark APIs.
///
/// This replaces the manual 200+ line STARK protocol implementation with a single
/// call to p3_uni_stark::prove(), which handles all phases automatically:
/// - Phase 1: Commit main trace
/// - Phase 2: Sample challenges & commit aux trace (if applicable)
/// - Phase 3: Compute and commit quotient polynomials
/// - Phase 4: Open at evaluation point
pub fn prove_poseidon2(trace: ExecutionTrace) -> Vec<u8> {
    let air = ProcessorAir;
    let public_values = vec![];

    // Convert trace from column-major to row-major format
    let trace_row_major = to_row_major(&trace);
    let degree = trace_row_major.height();
    let log_degree = log2_strict_usize(degree);

    // Generate Poseidon2 configuration with dynamic FRI parameters
    let config = generate_poseidon2_config(log_degree, 8); // constraint_degree = 8

    // Prove using p3-uni-stark - this single call replaces 200+ lines of manual protocol
    let proof = p3_uni_stark::prove(&config, &air, &trace_row_major, &public_values);

    // Serialize proof to bytes
    bincode::serialize(&proof).expect("failed to serialize proof")
}

/// Generate Poseidon2 STARK configuration with deterministic random constants.
///
/// Uses a fixed seed (0) for reproducibility - the same constants must be used
/// by both prover and verifier.
pub fn generate_poseidon2_config(
    log_degree: usize,
    constraint_degree: usize,
) -> StarkConfigPoseidon {
    use rand::{SeedableRng, rngs::StdRng};

    // Create RNG with fixed seed for reproducible constants
    let mut rng = StdRng::seed_from_u64(0);

    // Generate Poseidon2 round constants
    let external_constants = ExternalLayerConstants::new_from_rng(HALF_FULL_ROUNDS * 2, &mut rng);
    let internal_constants: Vec<Val> =
        (0..PARTIAL_ROUNDS).map(|_| Val::from_u64(rng.random())).collect();

    // Create Poseidon2 permutation and hash/compress functions
    let perm = Perm::new(external_constants, internal_constants);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());

    // Build Merkle tree MMCS for commitments
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    // Compute FRI parameters dynamically based on trace size
    // For small test traces, reduce parameters to satisfy:
    //   log_degree > log_final_poly_len + log_blowup
    let log_quotient_degree = log2_ceil_usize(constraint_degree - 1);
    let log_blowup = log_quotient_degree.max(1);
    let log_final_poly_len = if log_degree > log_blowup + 2 {
        (log_degree - log_blowup - 1).min(2)
    } else {
        0
    };

    let fri_config = FriParameters {
        log_blowup,
        log_final_poly_len,
        num_queries: 27,
        proof_of_work_bits: 16,
        log_folding_factor: 1,
        mmcs: challenge_mmcs,
    };

    let pcs = FriPcs::new(dft, val_mmcs, fri_config);
    let challenger = Challenger::new(perm);

    StarkConfigPoseidon::new(pcs, challenger)
}
