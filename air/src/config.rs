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

/// Relation digest absorbed into the Fiat-Shamir transcript domain separator.
pub type RelationDigest = [Felt; 4];

/// RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID, ACE_CIRCUIT_REGISTRY_ROOT]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
pub const RELATION_DIGEST: RelationDigest = [
    Felt::new_unchecked(6228634522968454696),
    Felt::new_unchecked(9493741029039437490),
    Felt::new_unchecked(16565065039104926463),
    Felt::new_unchecked(1338979827357058143),
];

/// Root of the accepted ACE circuit registry.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
pub const ACE_CIRCUIT_REGISTRY_ROOT: [Felt; 4] = [
    Felt::new_unchecked(6703562205535399821),
    Felt::new_unchecked(4902180974408534340),
    Felt::new_unchecked(2376205887554034497),
    Felt::new_unchecked(2131879092839069624),
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
        Felt::new_unchecked(14950454962026649157),
        Felt::new_unchecked(18381334423201801371),
        Felt::new_unchecked(3505576435670816154),
        Felt::new_unchecked(10492020312020072697),
    ],
    [
        Felt::new_unchecked(16360681022883134878),
        Felt::new_unchecked(3383008486129604525),
        Felt::new_unchecked(12128423521814793071),
        Felt::new_unchecked(15484732731492441141),
    ],
    [
        Felt::new_unchecked(9558598998948809127),
        Felt::new_unchecked(5625297958135351357),
        Felt::new_unchecked(6045843798313457949),
        Felt::new_unchecked(11084501094466476362),
    ],
    [
        Felt::new_unchecked(7246951904958279967),
        Felt::new_unchecked(9113637511529023284),
        Felt::new_unchecked(6771609253107818884),
        Felt::new_unchecked(9655557337986743765),
    ],
    [
        Felt::new_unchecked(5400103277155201926),
        Felt::new_unchecked(13221982994882074493),
        Felt::new_unchecked(4281571135509886317),
        Felt::new_unchecked(8539761392286494695),
    ],
    [
        Felt::new_unchecked(15834849235453051024),
        Felt::new_unchecked(14635731417693870212),
        Felt::new_unchecked(2486581593759991827),
        Felt::new_unchecked(2068667486060323890),
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
/// domain-separated transcript initialization. The config factories bind the
/// caller-supplied relation digest into the prototype challenger; this function
/// adds the remaining protocol parameters.
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

/// Concrete STARK configuration type for RPO.
pub type RpoConfig = MidenStarkConfig<AlgLmcs<RpoPermutation256>, AlgChallenger<RpoPermutation256>>;

/// Concrete STARK configuration type for Poseidon2.
pub type Poseidon2Config =
    MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>>;

/// Concrete STARK configuration type for RPX.
pub type RpxConfig = MidenStarkConfig<AlgLmcs<RpxPermutation256>, AlgChallenger<RpxPermutation256>>;

/// Creates an RPO-based STARK configuration bound to `relation_digest`.
pub fn rpo_config(params: PcsParams, relation_digest: RelationDigest) -> RpoConfig {
    alg_config(params, RpoPermutation256, relation_digest)
}

/// Creates a Poseidon2-based STARK configuration bound to `relation_digest`.
pub fn poseidon2_config(params: PcsParams, relation_digest: RelationDigest) -> Poseidon2Config {
    alg_config(params, Poseidon2Permutation256, relation_digest)
}

/// Creates an RPX-based STARK configuration bound to `relation_digest`.
pub fn rpx_config(params: PcsParams, relation_digest: RelationDigest) -> RpxConfig {
    alg_config(params, RpxPermutation256, relation_digest)
}

/// Internal helper: builds an algebraic STARK configuration from a permutation.
///
/// The prototype challenger has the relation digest pre-loaded in the sponge capacity.
/// When `observe_protocol_params` is called, the first duplexing permutes this
/// capacity together with the PCS parameters written into the rate.
fn alg_config<P>(
    params: PcsParams,
    perm: P,
    relation_digest: RelationDigest,
) -> MidenStarkConfig<AlgLmcs<P>, AlgChallenger<P>>
where
    P: CryptographicPermutation<[Felt; SPONGE_WIDTH]> + Copy,
{
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let mut state = [Felt::ZERO; SPONGE_WIDTH];
    state[CAPACITY_RANGE].copy_from_slice(&relation_digest);
    let challenger = DuplexChallenger {
        sponge_state: state,
        input_buffer: vec![],
        output_buffer: vec![],
        permutation: perm,
    };
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
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
    extern crate alloc;
    use alloc::vec::Vec;

    use miden_core::{Felt, Word, crypto::hash::Poseidon2};
    use miden_crypto::merkle::MerkleTree;

    use crate::{ProofOrder, ace};

    const PROTOCOL_ID: u64 = 1;
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
