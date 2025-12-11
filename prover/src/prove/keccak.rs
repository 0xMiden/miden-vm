// Keccak prover using p3-uni-stark APIs
//
// This implementation replaces the manual STARK protocol with Plonky3's high-level
// p3_uni_stark::prove() function, reducing code from 220 lines to ~80 lines.

use alloc::{vec, vec::Vec};

use miden_air::{Felt, ProcessorAir};
use miden_processor::ExecutionTrace;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;

use super::utils::to_row_major;

type Val = Felt;
type Challenge = BinomialExtensionField<Val, 2>;

pub type ByteHash = Keccak256Hash; // Standard Keccak for byte hashing
pub type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>; // Keccak optimized for field elements
pub type FieldHash = SerializingHasher<U64Hash>; // Wrapper for field element hashing
pub type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
pub type ValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    4,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
pub type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type StarkConfigKeccak = StarkConfig<FriPcs, Challenge, Challenger>;

/// Prove execution using Keccak hash function and p3-uni-stark APIs.
///
/// This replaces the manual 220-line STARK protocol implementation with a single
/// call to p3_uni_stark::prove(), which handles all phases automatically:
/// - Phase 1: Commit main trace
/// - Phase 2: Sample challenges & commit aux trace (if applicable)
/// - Phase 3: Compute and commit quotient polynomials
/// - Phase 4: Open at evaluation point
pub fn prove_keccak(trace: ExecutionTrace) -> Vec<u8> {
    let air = ProcessorAir;
    let public_values = vec![];

    // Convert trace from column-major to row-major format
    let trace_row_major = to_row_major(&trace);

    // Generate Keccak configuration
    let config = generate_keccak_config();

    // Prove using p3-uni-stark - this single call replaces 150+ lines of manual protocol
    let proof = p3_uni_stark::prove(&config, &air, &trace_row_major, &public_values);

    // Serialize proof to bytes
    bincode::serialize(&proof).expect("failed to serialize proof")
}

/// Generate Keccak STARK configuration.
///
/// Uses Keccak-256 for byte hashing and KeccakF permutation optimized for field
/// elements with fixed FRI parameters tuned for production use (27 queries, 96-bit security).
pub fn generate_keccak_config() -> StarkConfigKeccak {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let compress = MyCompress::new(u64_hash);

    let field_hash = FieldHash::new(u64_hash);
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

    let challenger = Challenger::from_hasher(vec![], byte_hash);

    StarkConfigKeccak::new(pcs, challenger)
}
