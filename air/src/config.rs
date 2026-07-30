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
/// Proof-of-work bits for query phase, calibrated so that with 27 queries
/// `conjectured_security_level(27, 17) == 96`, with no margin: lowering this or the per-query
/// rate drops the preset below 96 conjectured bits.
const QUERY_POW_BITS: usize = 17;

// CONJECTURED SECURITY LEVEL
// ================================================================================================

/// Fixed-point (16 fractional bits) conjectured security bits contributed per FRI query, for
/// this configuration's blowup (8) and challenge field (~128 bits):
/// `floor(-log2(rho + eta) * 2^16)` with `rho = 1/8` and the random-words cutoff
/// `eta = log2(e/rho) * rho / 128` (<https://eprint.iacr.org/2025/2010>, section 1.5), i.e.
/// ~2.9508 bits per query. Must match the constant in `crates/lib/core/asm/sys/vm/mod.masm`
/// (enforced by cross-tests).
pub const CONJECTURED_BITS_PER_QUERY_FP: u64 = 193_382;

/// Cap on any reported security level: the minimum of the challenge-field size and the
/// commitment hash's collision resistance (both ~128 bits here).
pub const MAX_SECURITY_LEVEL: u32 = 128;

/// Returns the conjectured security level (in bits) attained by a proof with the given FRI
/// query count and query-phase grinding bits, under this configuration's fixed blowup and
/// challenge field.
///
/// The computation is integer fixed-point — `min((num_queries * C) >> 16 + query_pow, 128)` —
/// so the MASM mirror can match it bit-for-bit; the constant is floored, so the result never
/// exceeds the real-valued formula (conservative by at most one bit). `num_queries` is a FRI
/// query count (the verifier bounds it to `<= 150`), so the product fits comfortably in a `u32`.
pub fn conjectured_security_level(num_queries: u32, query_pow_bits: u32) -> u32 {
    let fri_bits = ((num_queries as u64 * CONJECTURED_BITS_PER_QUERY_FP) >> 16) as u32;
    (fri_bits + query_pow_bits).min(MAX_SECURITY_LEVEL)
}

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

    /// The integer fixed-point conjectured-security computation must reproduce the
    /// reference values of the random-words formula (2025/2010, section 1.5), precomputed
    /// externally; in particular the calibration points (27, 16) -> 95 and (27, 17) -> 96.
    #[test]
    fn conjectured_security_level_matches_reference_vectors() {
        static VECTORS: &[(u32, u32, u32)] = &[
            (1, 0, 2),
            (1, 4, 6),
            (1, 16, 18),
            (1, 17, 19),
            (1, 24, 26),
            (1, 30, 32),
            (1, 100, 102),
            (5, 0, 14),
            (5, 4, 18),
            (5, 16, 30),
            (5, 17, 31),
            (5, 24, 38),
            (5, 30, 44),
            (5, 100, 114),
            (22, 0, 64),
            (22, 4, 68),
            (22, 16, 80),
            (22, 17, 81),
            (22, 24, 88),
            (22, 30, 94),
            (22, 100, 128),
            (27, 0, 79),
            (27, 4, 83),
            (27, 16, 95),
            (27, 17, 96),
            (27, 24, 103),
            (27, 30, 109),
            (27, 100, 128),
            (28, 0, 82),
            (28, 4, 86),
            (28, 16, 98),
            (28, 17, 99),
            (28, 24, 106),
            (28, 30, 112),
            (28, 100, 128),
            (43, 0, 126),
            (43, 4, 128),
            (43, 16, 128),
            (43, 17, 128),
            (43, 24, 128),
            (43, 30, 128),
            (43, 100, 128),
            (64, 0, 128),
            (64, 16, 128),
            (100, 0, 128),
            (128, 24, 128),
            (150, 0, 128),
            (150, 100, 128),
            (255, 0, 128),
        ];
        for &(q, pow, expected) in VECTORS {
            assert_eq!(
                super::conjectured_security_level(q, pow),
                expected,
                "conjectured_security_level({q}, {pow})"
            );
        }
    }

    /// The fixed-point estimator must never overstate security relative to the true random-words
    /// f64 formula, and must track it within one bit. This guards the conservative direction (the
    /// dangerous one) against any future recalibration of `CONJECTURED_BITS_PER_QUERY_FP`.
    #[test]
    fn conjectured_security_level_never_overstates_true_formula() {
        // The true per-query rate `b = -log2(rho + eta)` with `rho = 1/8` (blowup 8) and the
        // random-words cutoff `eta = log2(e/rho) * rho / 128` (2025/2010, section 1.5).
        let rho = 0.125_f64;
        let eta = (core::f64::consts::LOG2_E + 3.0) * rho / 128.0;
        let bits_per_query = -(rho + eta).log2();

        // The compiled constant is exactly that rate in 16-fractional-bit fixed point.
        assert_eq!(
            super::CONJECTURED_BITS_PER_QUERY_FP,
            (bits_per_query * 65536.0).floor() as u64,
            "CONJECTURED_BITS_PER_QUERY_FP is stale relative to the random-words rate"
        );

        // Over the whole verifier domain (num_queries a u8, query_pow_bits < 32) the fixed-point
        // level never exceeds the f64 formula and trails it by at most one bit.
        for nq in 0u32..256 {
            for pow in 0u32..32 {
                let float_fri = (f64::from(nq) * bits_per_query) as u32;
                let float_level = (float_fri + pow).min(super::MAX_SECURITY_LEVEL);
                let fixed_level = super::conjectured_security_level(nq, pow);
                let delta = i64::from(float_level) - i64::from(fixed_level);
                assert!(
                    (0..=1).contains(&delta),
                    "num_queries={nq}, query_pow_bits={pow}: float={float_level}, \
                     fixed={fixed_level} (delta={delta})"
                );
            }
        }
    }
}
