//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_crypto::stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, Word, field::QuadFelt};
use miden_crypto::{
    field::Field,
    hash::{
        blake::Blake3Hasher,
        keccak::{Keccak256Hash, KeccakF, VECTOR_LEN},
        poseidon2::Poseidon2Permutation256,
        rpo::RpoPermutation256,
        rpx::RpxPermutation256,
    },
    merkle::MerkleTree,
    stark::{
        GenericStarkConfig,
        challenger::{CanObserve, DuplexChallenger, HashChallenger, SerializingChallenger64},
        dft::Radix2DitParallel,
        hasher::{ChainingHasher, SerializingStatefulSponge, StatefulSponge},
        lmcs::config::LmcsConfig,
        pcs::PcsParams,
        symmetric::{
            CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge,
            TruncatedPermutation,
        },
    },
};

use crate::{PROOF_ORDER_COUNT, PROOF_ORDER_REGISTRY_DEPTH};

// SHARED TYPES
// ================================================================================================

/// Miden VM STARK configuration with pre-filled common type parameters.
///
/// All Miden configurations use `Felt` as the base field, `QuadFelt` as the extension field,
/// and `Radix2DitParallel<Felt>` as the DFT. Only the LMCS commitment scheme (`L`) and
/// Fiat-Shamir challenger (`Ch`) vary by hash function.
pub type MidenStarkConfig<L, Ch> =
    GenericStarkConfig<Felt, QuadFelt, L, Radix2DitParallel<Felt>, Ch>;

type PackedFelt = <Felt as Field>::Packing;

/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// PCS PARAMETERS
// ================================================================================================

/// Log2 of the FRI blowup factor (blowup = 8).
const LOG_BLOWUP: u8 = 3;
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
/// Proof-of-work bits for query phase.
const QUERY_POW_BITS: usize = 16;

/// Default PCS parameters shared by all hash function configurations.
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

/// RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID, ACE_CIRCUIT_REGISTRY_ROOT]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
pub const RELATION_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(1054594910562052599),
    Felt::new_unchecked(11984096228624862183),
    Felt::new_unchecked(16222035304856376939),
    Felt::new_unchecked(17104265933749949296),
];

/// Root of the accepted ACE circuit registry.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
pub const ACE_CIRCUIT_REGISTRY_ROOT: [Felt; 4] = [
    Felt::new_unchecked(15847950920222870147),
    Felt::new_unchecked(7047508041269431782),
    Felt::new_unchecked(16167476278294667840),
    Felt::new_unchecked(12153679197399633766),
];

/// Smallest ACE circuit registry depth covering every proof-order tag.
///
/// With `n` AIRs, proof-order tags range over the `n!` AIR permutations.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = PROOF_ORDER_REGISTRY_DEPTH;

/// Number of leaves in the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_LEAF_COUNT: usize = 1 << ACE_CIRCUIT_REGISTRY_DEPTH;
const _: () = assert!(
    PROOF_ORDER_COUNT <= ACE_CIRCUIT_REGISTRY_LEAF_COUNT,
    "ACE_CIRCUIT_REGISTRY_DEPTH must cover every proof-order variant",
);

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: &[[Felt; 4]] = &[
    [
        Felt::new_unchecked(14350200979877962472),
        Felt::new_unchecked(103089701495165480),
        Felt::new_unchecked(9854064066123798283),
        Felt::new_unchecked(12174181773921540602),
    ],
    [
        Felt::new_unchecked(5246651242980857613),
        Felt::new_unchecked(1618297549716024731),
        Felt::new_unchecked(1061405701969296361),
        Felt::new_unchecked(17297391313466625441),
    ],
    [
        Felt::new_unchecked(16036278270407702678),
        Felt::new_unchecked(8080086475134229442),
        Felt::new_unchecked(17598264714838810328),
        Felt::new_unchecked(8480121305785686269),
    ],
    [
        Felt::new_unchecked(5978319484544539769),
        Felt::new_unchecked(11472236488368657853),
        Felt::new_unchecked(16907876063844059339),
        Felt::new_unchecked(16419555801865071852),
    ],
    [
        Felt::new_unchecked(15319518752942062709),
        Felt::new_unchecked(2570562416486635634),
        Felt::new_unchecked(16366026173493615048),
        Felt::new_unchecked(11052119545944915459),
    ],
    [
        Felt::new_unchecked(17327818317567783689),
        Felt::new_unchecked(5978149467245783274),
        Felt::new_unchecked(12627338572399706497),
        Felt::new_unchecked(13452413375315601834),
    ],
    [
        Felt::new_unchecked(1422687632582465263),
        Felt::new_unchecked(6762842649754512176),
        Felt::new_unchecked(204555358186721414),
        Felt::new_unchecked(14644894839315568530),
    ],
    [
        Felt::new_unchecked(17922044667460564880),
        Felt::new_unchecked(15528373781338840444),
        Felt::new_unchecked(17550563904831590003),
        Felt::new_unchecked(14149524031833665710),
    ],
];

pub fn ace_circuit_registry_tree() -> MerkleTree {
    let leaves = ACE_CIRCUIT_REGISTRY_LEAVES.iter().copied().map(Word::new).collect::<Vec<_>>();
    MerkleTree::new(&leaves).expect("ACE circuit registry has power-of-two leaves")
}

/// Observes PCS protocol parameters into the challenger.
///
/// Call on a challenger obtained from `config.challenger()` to complete the
/// domain-separated transcript initialization. The config factories already bind
/// RELATION_DIGEST into the prototype challenger; this function adds the remaining
/// protocol parameters.
pub fn observe_protocol_params(challenger: &mut impl CanObserve<Felt>) {
    // Batch 1: PCS parameters, zero-padded to SPONGE_RATE.
    challenger.observe(Felt::new_unchecked(NUM_QUERIES as u64));
    challenger.observe(Felt::new_unchecked(QUERY_POW_BITS as u64));
    challenger.observe(Felt::new_unchecked(DEEP_POW_BITS as u64));
    challenger.observe(Felt::new_unchecked(FOLDING_POW_BITS as u64));
    challenger.observe(Felt::new_unchecked(LOG_BLOWUP as u64));
    challenger.observe(Felt::new_unchecked(LOG_FINAL_DEGREE as u64));
    challenger.observe(Felt::new_unchecked(1_u64 << LOG_FOLDING_ARITY));
    challenger.observe(Felt::ZERO);
}

// ALGEBRAIC HASHES (RPO, Poseidon2, RPX)
// ================================================================================================

/// Sponge state width in field elements.
const SPONGE_WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const SPONGE_RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST_WIDTH: usize = 4;
/// Range of capacity slots within the sponge state array.
const CAPACITY_RANGE: core::ops::Range<usize> = SPONGE_RATE..SPONGE_WIDTH;

/// Algebraic LMCS (for RPO, Poseidon2, RPX).
type AlgLmcs<P> = LmcsConfig<
    PackedFelt,
    PackedFelt,
    StatefulSponge<P, SPONGE_WIDTH, SPONGE_RATE, DIGEST_WIDTH>,
    TruncatedPermutation<P, COMPRESSION_INPUTS, DIGEST_WIDTH, SPONGE_WIDTH>,
    SPONGE_WIDTH,
    DIGEST_WIDTH,
>;

/// Algebraic duplex challenger (for RPO, Poseidon2, RPX).
type AlgChallenger<P> = DuplexChallenger<Felt, P, SPONGE_WIDTH, SPONGE_RATE>;

/// Concrete STARK configuration type for Poseidon2.
pub type Poseidon2Config =
    MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>>;

/// Creates an RPO-based STARK configuration.
pub fn rpo_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpoPermutation256>, AlgChallenger<RpoPermutation256>> {
    let mut config = alg_config(params, RpoPermutation256);
    config.lmcs = config.lmcs.with_rpo_acceleration();
    config
}

/// Creates a Poseidon2-based STARK configuration.
pub fn poseidon2_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>> {
    alg_config(params, Poseidon2Permutation256)
}

/// Creates an RPX-based STARK configuration.
pub fn rpx_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpxPermutation256>, AlgChallenger<RpxPermutation256>> {
    alg_config(params, RpxPermutation256)
}

/// Internal helper: builds an algebraic STARK configuration from a permutation.
///
/// The prototype challenger has RELATION_DIGEST pre-loaded in the sponge capacity.
/// When `observe_protocol_params` is called, the first duplexing permutes this
/// capacity together with the PCS parameters written into the rate.
fn alg_config<P>(params: PcsParams, perm: P) -> MidenStarkConfig<AlgLmcs<P>, AlgChallenger<P>>
where
    P: CryptographicPermutation<[Felt; SPONGE_WIDTH]> + Copy,
{
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let mut state = [Felt::ZERO; SPONGE_WIDTH];
    state[CAPACITY_RANGE].copy_from_slice(&RELATION_DIGEST);
    let challenger = DuplexChallenger {
        sponge_state: state,
        input_buffer: vec![],
        output_buffer: vec![],
        permutation: perm,
    };
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

#[cfg(all(test, feature = "metal", target_os = "macos"))]
mod rpo_metal_tests {
    use miden_crypto::{
        hash::rpo::RpoPermutation256,
        stark::{
            StarkConfig,
            lmcs::{Lmcs, LmcsTree},
            matrix::RowMajorMatrix,
        },
    };

    use super::*;

    fn matrix(height: usize, width: usize, offset: u64) -> RowMajorMatrix<Felt> {
        let values = (0..height * width)
            .map(|i| {
                let value = offset + (i as u64 * 0x1_0000_0001) + ((i as u64) << 7);
                Felt::new_unchecked(value)
            })
            .collect();
        RowMajorMatrix::new(values, width)
    }

    #[test]
    fn rpo_metal_lmcs_root_matches_cpu_lmcs() {
        let scenarios = [
            vec![matrix(16, 8, 5)],
            vec![matrix(16, 16, 13)],
            vec![matrix(8, 7, 3), matrix(8, 16, 31), matrix(8, 23, 311)],
            vec![matrix(2, 3, 11), matrix(4, 9, 101), matrix(8, 17, 1001)],
            vec![matrix(16, 12, 7), matrix(32, 16, 17), matrix(64, 31, 27)],
            vec![matrix(16_384, 3, 19), matrix(32_768, 8, 29)],
        ];

        for leaves in scenarios {
            let cpu_config = alg_config(pcs_params(), RpoPermutation256);
            let metal_config = rpo_config(pcs_params());

            let cpu_tree = cpu_config.lmcs().build_aligned_tree(leaves.clone());
            let metal_tree = metal_config.lmcs().build_aligned_tree(leaves);

            assert_eq!(cpu_tree.root(), metal_tree.root());
        }
    }
}

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

/// Creates a Blake3_256-based STARK configuration.
pub fn blake3_256_config(params: PcsParams) -> MidenStarkConfig<BlakeLmcs, BlakeChallenger> {
    let lmcs = LmcsConfig::new(
        ChainingHasher::new(Blake3Hasher),
        CompressionFunctionFromHasher::new(Blake3Hasher),
    );
    let mut challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
    challenger.observe_slice(&RELATION_DIGEST);
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

/// Creates a Keccak-based STARK configuration.
///
/// Uses the stateful binary sponge with the Keccak permutation and `[Felt; VECTOR_LEN]` packing
/// for SIMD parallelization.
pub fn keccak_config(params: PcsParams) -> MidenStarkConfig<KeccakLmcs, KeccakChallenger> {
    let mmcs_sponge = KeccakMmcsSponge::new(KeccakF {});
    let compress = CompressionFunctionFromHasher::new(mmcs_sponge);
    let sponge = SerializingStatefulSponge::new(StatefulSponge::new(KeccakF {}));
    let lmcs = LmcsConfig::new(sponge, compress);
    let mut challenger = SerializingChallenger64::from_hasher(vec![], Keccak256Hash {});
    challenger.observe_slice(&RELATION_DIGEST);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use miden_core::{Felt, Word, crypto::hash::Poseidon2};
    use miden_crypto::merkle::MerkleTree;

    use crate::{ProofOrder, ace};

    const PROTOCOL_ID: u64 = 0;
    const ACE_REGISTRY_PADDING_DOMAIN: u64 = 0xace;
    const REGEN_HINT: &str = "cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write";

    fn padding_leaf(index: usize) -> Word {
        Poseidon2::hash_elements(&[
            Felt::new_unchecked(ACE_REGISTRY_PADDING_DOMAIN),
            Felt::new_unchecked(index as u64),
        ])
    }

    /// Snapshot test: catches any AIR change that alters the constraint circuit.
    ///
    /// If this test fails, regenerate with:
    /// ```text
    /// cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write
    /// ```
    #[test]
    fn relation_digest_matches_current_air() {
        assert_eq!(
            super::ACE_CIRCUIT_REGISTRY_LEAVES.len(),
            super::ACE_CIRCUIT_REGISTRY_LEAF_COUNT,
            "ACE_CIRCUIT_REGISTRY_LEAVES in config.rs is stale. Regenerate with: {REGEN_HINT}",
        );

        let mut expected_leaves = (0..super::ACE_CIRCUIT_REGISTRY_LEAF_COUNT)
            .map(padding_leaf)
            .collect::<Vec<_>>();
        let mut snapshot_lines = Vec::new();
        let mut expected_metadata = None;

        for order in ProofOrder::variants() {
            let circuit = ace::build_recursive_verifier_ace_circuit(&order).unwrap();
            let metadata = (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len);
            if let Some(expected) = expected_metadata {
                assert_eq!(metadata, expected, "ACE circuit metadata must be uniform");
            } else {
                expected_metadata = Some(metadata);
            }

            let tag = order.tag() as usize;
            assert!(tag < expected_leaves.len(), "proof-order tag does not fit registry tree");
            expected_leaves[tag] = circuit.commitment;

            let commitment: Vec<u64> =
                circuit.commitment.iter().map(Felt::as_canonical_u64).collect();
            snapshot_lines.push(format!(
                "{}:\n  num_inputs: {}\n  num_eval_gates: {}\n  stream_len: {}\n  commitment: {:?}",
                order.file_stem(),
                circuit.num_inputs,
                circuit.num_eval_gates,
                circuit.stream_len,
                commitment,
            ));
        }

        let actual_leaves = super::ACE_CIRCUIT_REGISTRY_LEAVES
            .iter()
            .copied()
            .map(Word::new)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_leaves.as_slice(),
            expected_leaves.as_slice(),
            "ACE_CIRCUIT_REGISTRY_LEAVES in config.rs is stale. Regenerate with: {REGEN_HINT}",
        );

        let tree = MerkleTree::new(expected_leaves).expect("registry tree");
        let registry_root = tree.root();
        assert_eq!(
            Word::new(super::ACE_CIRCUIT_REGISTRY_ROOT),
            registry_root,
            "ACE_CIRCUIT_REGISTRY_ROOT in config.rs is stale. Regenerate with: {REGEN_HINT}"
        );

        let relation_input: Vec<Felt> = core::iter::once(Felt::new_unchecked(PROTOCOL_ID))
            .chain(registry_root.iter().copied())
            .collect();
        let digest = Poseidon2::hash_elements(&relation_input);
        let expected: Vec<u64> = digest.iter().map(Felt::as_canonical_u64).collect();

        let snapshot = format!("{}\nrelation_digest: {:?}", snapshot_lines.join("\n"), expected);
        insta::assert_snapshot!(snapshot);

        let actual: Vec<u64> = super::RELATION_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, expected,
            "RELATION_DIGEST in config.rs is stale. Regenerate with: {REGEN_HINT}"
        );
    }
}
