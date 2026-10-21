//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_lifted_stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::vec;

use miden_core::{Felt, Word, field::QuadFelt, program::domain::STARK_TRANSCRIPT};
use miden_crypto::hash::{
    blake::Blake3Hasher,
    eidos::{Eidos, EidosLmcsCompressor, EidosLmcsHasher, MidenEidosChallenger, PACKED_LANES},
    keccak::{Keccak256Hash, KeccakF, VECTOR_LEN},
    stateful::{ChainingHasher, SerializingStatefulSponge, StatefulSponge},
};
use miden_lifted_stark::{GenericStarkConfig, lmcs::config::LmcsConfig, pcs::PcsParams};
use p3_challenger::{CanObserve, HashChallenger, SerializingChallenger64};
use p3_dft::Radix2DitParallel;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge};

// SHARED TYPES
// ================================================================================================

/// Miden VM STARK configuration with pre-filled common type parameters.
///
/// All Miden configurations use `Felt` as the base field, `QuadFelt` as the extension field,
/// and `Radix2DitParallel<Felt>` as the DFT. Only the LMCS commitment scheme (`L`) and
/// Fiat-Shamir challenger (`Ch`) vary by hash function.
pub type MidenStarkConfig<L, Ch> =
    GenericStarkConfig<Felt, QuadFelt, L, Radix2DitParallel<Felt>, Ch>;

/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// PCS PARAMETERS
// ================================================================================================

/// Base-two logarithm of the low-degree extension blowup used by canonical VM proofs.
pub const LOG_BLOWUP: u8 = 3;
/// Log2 of the FRI folding arity (arity = 4).
pub const LOG_FOLDING_ARITY: u8 = 2;
/// Log2 of the final polynomial degree (degree = 128).
const LOG_FINAL_DEGREE: u8 = 7;
/// Proof-of-work bits for FRI folding challenges.
pub const FOLDING_POW_BITS: usize = 4;
/// Proof-of-work bits for DEEP composition polynomial.
pub const DEEP_POW_BITS: usize = 12;
/// Number of FRI query repetitions.
const NUM_QUERIES: usize = 27;
/// Proof-of-work bits for the query phase. Together with 27 queries, this gives the query round
/// exactly 96 conjectured bits; lowering either value drops the preset below that target.
const QUERY_POW_BITS: usize = 17;

/// Default PCS parameters shared by all hash function configurations.
///
/// These are protocol constants. They must not depend on the process environment or benchmark
/// settings because the same factory is used by production provers and verifiers.
pub fn pcs_params() -> PcsParams {
    PcsParams::new(
        LOG_BLOWUP,
        LOG_FOLDING_ARITY,
        LOG_FINAL_DEGREE,
        FOLDING_POW_BITS,
        DEEP_POW_BITS,
        NUM_QUERIES,
        QUERY_POW_BITS,
    )
    .expect("invalid PCS parameters")
}

// DOMAIN-SEPARATED FIAT-SHAMIR TRANSCRIPT
// ================================================================================================

/// Relation digest absorbed into the Fiat-Shamir transcript domain separator.
pub type RelationDigest = [Felt; 4];

/// Version of the VM external multi-AIR statement semantics.
pub const PROTOCOL_ID: u64 = 1;

/// Bind a protocol version and the canonical ACE circuit commitment into a relation digest.
pub fn relation_digest(protocol_id: u64, circuit_digest: &Word) -> RelationDigest {
    let input = [
        Felt::new_unchecked(protocol_id),
        circuit_digest[0],
        circuit_digest[1],
        circuit_digest[2],
        circuit_digest[3],
    ];
    let digest = Eidos::hash_elements(&input);
    let elements = digest.as_elements();
    [elements[0], elements[1], elements[2], elements[3]]
}

/// Observes PCS protocol parameters into the challenger.
///
/// Call on a challenger obtained from `config.challenger()` to complete the
/// domain-separated transcript initialization. The config factories bind the
/// caller-supplied relation digest into the prototype challenger; this function
/// adds the actual PCS parameters used by that config.
pub fn observe_protocol_params(params: &PcsParams, challenger: &mut impl CanObserve<Felt>) {
    // Observe the eight PCS parameters, including a trailing zero.
    challenger.observe(Felt::new_unchecked(params.num_queries() as u64));
    challenger.observe(Felt::new_unchecked(params.query_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.deep_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.folding_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.log_blowup() as u64));
    challenger.observe(Felt::new_unchecked(params.log_final_degree() as u64));
    challenger.observe(Felt::new_unchecked(1_u64 << params.log_folding_arity()));
    challenger.observe(Felt::ZERO);
}

/// Default commitment alignment, in base-field elements.
pub const SPONGE_RATE: usize = miden_crypto::hash::eidos::BLOCK_LEN;
/// Number of base-field elements in a digest.
pub const DIGEST_WIDTH: usize = 4;

// BLAKE3
// ================================================================================================

/// Digest size in bytes for Blake3.
const BLAKE_DIGEST_SIZE: usize = 32;

/// Blake3 LMCS.
type BlakeLmcs = LmcsConfig<
    Felt,
    u8,
    ChainingHasher<Blake3Hasher>,
    CompressionFunctionFromHasher<Blake3Hasher, COMPRESSION_INPUTS, BLAKE_DIGEST_SIZE>,
    BLAKE_DIGEST_SIZE,
    BLAKE_DIGEST_SIZE,
>;

/// Blake3 challenger.
type BlakeChallenger =
    SerializingChallenger64<Felt, HashChallenger<u8, Blake3Hasher, BLAKE_DIGEST_SIZE>>;

/// Concrete STARK configuration type for Blake3.
pub type Blake3Config = MidenStarkConfig<BlakeLmcs, BlakeChallenger>;

/// Creates a Blake3_256-based STARK configuration bound to `relation_digest`.
pub fn blake3_256_config(params: PcsParams, relation_digest: RelationDigest) -> Blake3Config {
    let lmcs = LmcsConfig::new(
        ChainingHasher::new(Blake3Hasher),
        CompressionFunctionFromHasher::new(Blake3Hasher),
    );
    let mut challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
    challenger.observe_slice(&relation_digest);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

// EIDOS
// ================================================================================================

/// Eidos LMCS configuration with the VM's fixed digest and packed widths.
pub type EidosLmcs = LmcsConfig<
    [Felt; PACKED_LANES],
    [u64; PACKED_LANES],
    EidosLmcsHasher,
    EidosLmcsCompressor,
    4,
    4,
>;

/// Concrete STARK configuration type for Eidos.
pub type EidosConfig = MidenStarkConfig<EidosLmcs, MidenEidosChallenger>;

/// Creates an Eidos-based STARK configuration bound to `relation_digest`.
pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
    let lmcs: EidosLmcs = LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor);
    let transcript_init_cv = Eidos::transcript_init_cv(STARK_TRANSCRIPT);
    let challenger = MidenEidosChallenger::new(transcript_init_cv, relation_digest.into());
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

// KECCAK
// ================================================================================================

/// Keccak permutation state width (in u64 elements).
const KECCAK_WIDTH: usize = 25;
/// Keccak sponge rate (absorbable u64 elements per permutation).
const KECCAK_RATE: usize = 17;
/// Keccak digest width (in u64 elements).
const KECCAK_DIGEST: usize = 4;
/// Keccak-256 digest size in bytes (for the Fiat-Shamir challenger).
const KECCAK_CHALLENGER_DIGEST_SIZE: usize = 32;

/// Keccak MMCS sponge (padding-free, used for compression).
type KeccakMmcsSponge = PaddingFreeSponge<KeccakF, KECCAK_WIDTH, KECCAK_RATE, KECCAK_DIGEST>;

/// Keccak LMCS using the stateful binary sponge with `[Felt; VECTOR_LEN]` packing.
type KeccakLmcs = LmcsConfig<
    [Felt; VECTOR_LEN],
    [u64; VECTOR_LEN],
    SerializingStatefulSponge<StatefulSponge<KeccakF, KECCAK_WIDTH, KECCAK_RATE, KECCAK_DIGEST>>,
    CompressionFunctionFromHasher<KeccakMmcsSponge, COMPRESSION_INPUTS, KECCAK_DIGEST>,
    KECCAK_WIDTH,
    KECCAK_DIGEST,
>;

/// Keccak challenger.
type KeccakChallenger =
    SerializingChallenger64<Felt, HashChallenger<u8, Keccak256Hash, KECCAK_CHALLENGER_DIGEST_SIZE>>;

/// Concrete STARK configuration type for Keccak.
pub type KeccakConfig = MidenStarkConfig<KeccakLmcs, KeccakChallenger>;

/// Creates a Keccak-based STARK configuration.
///
/// Uses the stateful binary sponge with the Keccak permutation and `[Felt; VECTOR_LEN]` packing
/// for SIMD parallelization.
pub fn keccak_config(params: PcsParams, relation_digest: RelationDigest) -> KeccakConfig {
    let mmcs_sponge = KeccakMmcsSponge::new(KeccakF {});
    let compress = CompressionFunctionFromHasher::new(mmcs_sponge);
    let sponge = SerializingStatefulSponge::new(StatefulSponge::new(KeccakF {}));
    let lmcs = LmcsConfig::new(sponge, compress);
    let mut challenger = SerializingChallenger64::from_hasher(vec![], Keccak256Hash {});
    challenger.observe_slice(&relation_digest);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_crypto::{field::PrimeCharacteristicRing, hash::stateful::StatefulHasher};
    use miden_lifted_stark::lmcs::{Lmcs, LmcsTree, hiding_config::HidingLmcsConfig};
    use p3_matrix::{
        Matrix,
        bitrev::BitReversibleMatrix,
        dense::{RowMajorMatrix, RowMajorMatrixView},
    };
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;

    #[test]
    fn block_hashing_preserves_length_bound_salted_commitment() {
        let lmcs =
            HidingLmcsConfig::<[Felt; PACKED_LANES], [u64; PACKED_LANES], _, _, _, 4, 4, 4>::new(
                EidosLmcsHasher,
                EidosLmcsCompressor,
                SmallRng::seed_from_u64(42),
            );
        for with_prefix in [false, true] {
            let mut matrices = Vec::new();
            if with_prefix {
                matrices.push(RowMajorMatrix::new(vec![Felt::ONE; 3], 3));
            }
            matrices.push(RowMajorMatrix::new(
                (1..=2 * PACKED_LANES * 9).map(Felt::from_usize).collect(),
                9,
            ));
            let expected = lmcs.clone().build_aligned_tree(
                matrices.iter().map(|matrix| matrix.as_view().bit_reverse_rows()).collect(),
            );
            let expected_root = expected.root();
            drop(expected);
            let matrix = matrices.pop().unwrap();
            let actual = lmcs.clone().build_aligned_tree_with_blocks(
                matrices,
                matrix.dimensions(),
                |make_consumer| {
                    let consume = make_consumer.unwrap()(PACKED_LANES);
                    for (index, values) in
                        matrix.values.chunks_exact(PACKED_LANES * matrix.width()).enumerate()
                    {
                        consume(
                            index * PACKED_LANES,
                            RowMajorMatrixView::new(values, matrix.width()),
                        );
                    }
                    matrix
                },
            );
            assert_eq!(actual.root(), expected_root);
        }
    }

    #[test]
    fn lmcs_paths_bind_the_sum_of_independently_padded_rows() {
        let first = (1..=3).map(Felt::new_unchecked).collect::<Vec<_>>();
        let second = (4..=12).map(Felt::new_unchecked).collect::<Vec<_>>();
        let matrices = vec![
            RowMajorMatrix::new(first.clone(), first.len()),
            RowMajorMatrix::new(second.clone(), second.len()),
        ];
        let lmcs: EidosLmcs = LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor);

        let hasher = EidosLmcsHasher;
        let mut expected_state = [0; 4];
        <EidosLmcsHasher as StatefulHasher<Felt, [u64; 4]>>::initialize_state(
            &hasher,
            &mut expected_state,
            24,
        );
        <EidosLmcsHasher as StatefulHasher<Felt, [u64; 4]>>::absorb_into(
            &hasher,
            &mut expected_state,
            first.iter().copied(),
        );
        <EidosLmcsHasher as StatefulHasher<Felt, [u64; 4]>>::absorb_into(
            &hasher,
            &mut expected_state,
            second.iter().copied(),
        );

        let leaf = lmcs.hash([first.as_slice(), second.as_slice()]);
        assert_eq!(*leaf.as_ref(), expected_state);
        let tree = lmcs.build_tree(matrices.clone());
        let aligned_tree = lmcs.build_aligned_tree(matrices);
        assert_eq!(tree.root(), leaf);
        assert_eq!(aligned_tree.root(), leaf);
    }
}
