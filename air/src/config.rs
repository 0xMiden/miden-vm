//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_crypto::stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::vec;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    Word,
    field::Field,
    hash::{
        blake::Blake3Hasher,
        eidos::{Eidos, EidosLmcs, MidenEidosChallenger, lmcs_config},
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
/// Local benchmark override for the number of FRI query repetitions.
#[cfg(feature = "std")]
const BENCH_NUM_QUERIES_ENV: &str = "MIDEN_BENCH_NUM_FRI_QUERIES";
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
        num_queries(),
        QUERY_POW_BITS,
    )
    .expect("invalid PCS parameters")
}

fn num_queries() -> usize {
    #[cfg(feature = "std")]
    {
        if let Some(raw) = std::env::var(BENCH_NUM_QUERIES_ENV).ok().filter(|raw| !raw.is_empty()) {
            let value = raw
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{BENCH_NUM_QUERIES_ENV} must be a positive integer"));
            assert!(value > 0, "{BENCH_NUM_QUERIES_ENV} must be positive");
            return value;
        }
    }
    NUM_QUERIES
}

// DOMAIN-SEPARATED FIAT-SHAMIR TRANSCRIPT
// ================================================================================================

/// Root of the accepted ACE circuit registry.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// This root is absorbed into Fiat-Shamir as the relation identifier and authenticates the
/// ACE circuit selected by proof order.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
pub const RELATION_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(7045828122317569433),
    Felt::new_unchecked(7132650407329471410),
    Felt::new_unchecked(6456230347051898105),
    Felt::new_unchecked(2688922170926725303),
];

/// Depth of the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = 5;

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [
    [
        Felt::new_unchecked(4785669635872719226),
        Felt::new_unchecked(8389186217185723125),
        Felt::new_unchecked(2400139894462805977),
        Felt::new_unchecked(2206314816566483453),
    ],
    [
        Felt::new_unchecked(2725344507397499354),
        Felt::new_unchecked(532887144752114152),
        Felt::new_unchecked(5137689333509273383),
        Felt::new_unchecked(7336372371548966523),
    ],
    [
        Felt::new_unchecked(1041760178664270746),
        Felt::new_unchecked(7273761045765403809),
        Felt::new_unchecked(1353464130855742205),
        Felt::new_unchecked(4198031491075096114),
    ],
    [
        Felt::new_unchecked(4225765113319243790),
        Felt::new_unchecked(8549637123909553118),
        Felt::new_unchecked(5353080237634463661),
        Felt::new_unchecked(7877489414058790082),
    ],
    [
        Felt::new_unchecked(4638965460313823626),
        Felt::new_unchecked(8451221660667984227),
        Felt::new_unchecked(5218430084683371542),
        Felt::new_unchecked(5800321118587854928),
    ],
    [
        Felt::new_unchecked(6868978390114327407),
        Felt::new_unchecked(72095015076317500),
        Felt::new_unchecked(9044496372613220364),
        Felt::new_unchecked(1192728524995719875),
    ],
    [
        Felt::new_unchecked(7106964424053561243),
        Felt::new_unchecked(8725409312187945231),
        Felt::new_unchecked(2557416958518339700),
        Felt::new_unchecked(3123102117060161107),
    ],
    [
        Felt::new_unchecked(8883453190828171292),
        Felt::new_unchecked(7200062244688390199),
        Felt::new_unchecked(4216875135152895466),
        Felt::new_unchecked(4429690603770099775),
    ],
    [
        Felt::new_unchecked(2810580428159621795),
        Felt::new_unchecked(7631174452765790045),
        Felt::new_unchecked(132121192105163120),
        Felt::new_unchecked(3017432140905883580),
    ],
    [
        Felt::new_unchecked(1572898439521909677),
        Felt::new_unchecked(3184764909465766488),
        Felt::new_unchecked(5402436026522958232),
        Felt::new_unchecked(6870767971315823504),
    ],
    [
        Felt::new_unchecked(6654128514589276004),
        Felt::new_unchecked(564843845295422754),
        Felt::new_unchecked(8190670424636721131),
        Felt::new_unchecked(424469223515697758),
    ],
    [
        Felt::new_unchecked(5651175648900428200),
        Felt::new_unchecked(7812673714096443571),
        Felt::new_unchecked(3504291510453919655),
        Felt::new_unchecked(7641210691385459579),
    ],
    [
        Felt::new_unchecked(5994888958518425746),
        Felt::new_unchecked(3913774242843716741),
        Felt::new_unchecked(7309840159448708851),
        Felt::new_unchecked(7872528465197458089),
    ],
    [
        Felt::new_unchecked(7196125265924145355),
        Felt::new_unchecked(3994292023169495746),
        Felt::new_unchecked(8738259746888751285),
        Felt::new_unchecked(749563406505331398),
    ],
    [
        Felt::new_unchecked(1554506775653773513),
        Felt::new_unchecked(2821789291761786026),
        Felt::new_unchecked(7492470040910022994),
        Felt::new_unchecked(5061962739407541219),
    ],
    [
        Felt::new_unchecked(840039154640370199),
        Felt::new_unchecked(2552938408614049973),
        Felt::new_unchecked(6220792558058209889),
        Felt::new_unchecked(7029875766073357049),
    ],
    [
        Felt::new_unchecked(7727968403178029939),
        Felt::new_unchecked(167934368591764416),
        Felt::new_unchecked(5840159971893187309),
        Felt::new_unchecked(1758706786893227072),
    ],
    [
        Felt::new_unchecked(6930883348870954660),
        Felt::new_unchecked(7033003877227901823),
        Felt::new_unchecked(6905994061386113613),
        Felt::new_unchecked(4632021091316399138),
    ],
    [
        Felt::new_unchecked(3010463166381769503),
        Felt::new_unchecked(6892972538072609510),
        Felt::new_unchecked(8344577255846592561),
        Felt::new_unchecked(1849158122098182691),
    ],
    [
        Felt::new_unchecked(8703007247701742986),
        Felt::new_unchecked(8710246718850006316),
        Felt::new_unchecked(4946277468338308755),
        Felt::new_unchecked(3011173183963136424),
    ],
    [
        Felt::new_unchecked(6954843902865887972),
        Felt::new_unchecked(7820202189124649038),
        Felt::new_unchecked(1453689715402868714),
        Felt::new_unchecked(4849757723695868998),
    ],
    [
        Felt::new_unchecked(6562790365379084306),
        Felt::new_unchecked(169672827687878019),
        Felt::new_unchecked(5359860996656004418),
        Felt::new_unchecked(3354069678304522685),
    ],
    [
        Felt::new_unchecked(2116125019393456866),
        Felt::new_unchecked(601532261270745002),
        Felt::new_unchecked(2683560348734713297),
        Felt::new_unchecked(8466453938260550666),
    ],
    [
        Felt::new_unchecked(8919663476825280301),
        Felt::new_unchecked(258514918505892315),
        Felt::new_unchecked(7934841099324905378),
        Felt::new_unchecked(4862705171615171977),
    ],
    [
        Felt::new_unchecked(7492553050467963158),
        Felt::new_unchecked(8081088374960644000),
        Felt::new_unchecked(7764366953324756114),
        Felt::new_unchecked(3259324653549945952),
    ],
    [
        Felt::new_unchecked(4517398138128982474),
        Felt::new_unchecked(2799406181589145222),
        Felt::new_unchecked(6111024146617048628),
        Felt::new_unchecked(7251139791144741723),
    ],
    [
        Felt::new_unchecked(5541726244612396638),
        Felt::new_unchecked(5181673682555874186),
        Felt::new_unchecked(3640942250043376038),
        Felt::new_unchecked(1037479568157239402),
    ],
    [
        Felt::new_unchecked(611711009925292532),
        Felt::new_unchecked(6664482637915662948),
        Felt::new_unchecked(7951192821116100780),
        Felt::new_unchecked(7019507696344551482),
    ],
    [
        Felt::new_unchecked(5042236642266864694),
        Felt::new_unchecked(7175653782446700540),
        Felt::new_unchecked(8486414108342150992),
        Felt::new_unchecked(5978823857363690708),
    ],
    [
        Felt::new_unchecked(3242058117807811163),
        Felt::new_unchecked(3519411635101681901),
        Felt::new_unchecked(6516479801950969808),
        Felt::new_unchecked(5570051370036679692),
    ],
    [
        Felt::new_unchecked(8060917993458177133),
        Felt::new_unchecked(552925028612338687),
        Felt::new_unchecked(2672391830125088303),
        Felt::new_unchecked(2237293191537424071),
    ],
    [
        Felt::new_unchecked(5147153118388884767),
        Felt::new_unchecked(4667813816986934275),
        Felt::new_unchecked(1326206422901637309),
        Felt::new_unchecked(3415783592292225885),
    ],
];

/// Builds the ACE circuit registry tree accepted by the recursive verifier.
pub fn ace_circuit_registry_tree() -> MerkleTree {
    let leaves = ACE_CIRCUIT_REGISTRY_LEAVES.map(Word::new);
    MerkleTree::new(leaves).expect("ACE circuit registry has power-of-two leaves")
}

/// Observes PCS protocol parameters into the challenger.
///
/// Call on a challenger obtained from `config.challenger()` to complete the
/// domain-separated transcript initialization. The config factories already bind
/// RELATION_DIGEST into the prototype challenger; this function adds the remaining
/// protocol parameters.
pub fn observe_protocol_params(challenger: &mut impl CanObserve<Felt>) {
    // Batch 1: PCS parameters, zero-padded to SPONGE_RATE.
    challenger.observe(Felt::new_unchecked(num_queries() as u64));
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
    alg_config(params, RpoPermutation256)
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

// EIDOS
// ================================================================================================

/// Miden VM STARK transcript domain for the Eidos challenger.
const EIDOS_VM_STARK_TRANSCRIPT_V1: u32 = (2 << 8) | 1;

/// Creates an Eidos-based STARK configuration.
pub fn eidos_config(params: PcsParams) -> MidenStarkConfig<EidosLmcs, MidenEidosChallenger> {
    let lmcs = lmcs_config();
    let transcript_init_cv = Eidos::transcript_init_cv(EIDOS_VM_STARK_TRANSCRIPT_V1);
    let challenger = MidenEidosChallenger::new(transcript_init_cv, RELATION_DIGEST.into());
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

    use miden_core::Felt;
    use miden_crypto::{Word, hash::eidos::Eidos};

    use crate::{ProofOrder, ace};

    const ACE_REGISTRY_PADDING_DOMAIN: u64 = 0xace;
    const REGEN_HINT: &str = "cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write";

    /// Snapshot test: catches any AIR change that alters the constraint circuit.
    ///
    /// If this test fails, regenerate with:
    ///   cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints --
    /// --write
    #[test]
    fn relation_digest_matches_current_air() {
        let mut expected_leaves = (0..super::ACE_CIRCUIT_REGISTRY_LEAVES.len())
            .map(padding_leaf)
            .collect::<Vec<_>>();
        let mut snapshot_lines = Vec::new();
        let mut expected_metadata = None;

        for order in ProofOrder::variants() {
            let circuit = ace::build_recursive_verifier_ace_circuit(&order).unwrap();
            let circuit_commitment = [
                circuit.commitment[0],
                circuit.commitment[1],
                circuit.commitment[2],
                circuit.commitment[3],
            ];
            let metadata = (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len);
            if let Some(expected) = expected_metadata {
                assert_eq!(metadata, expected, "ACE circuit metadata must be uniform");
            } else {
                expected_metadata = Some(metadata);
            }

            let tag = order.tag() as usize;
            assert!(tag < ProofOrder::variants().len(), "invalid proof-order tag");
            expected_leaves[tag] = circuit.commitment;

            snapshot_lines.push(format!(
                "{}:\n  num_inputs: {}\n  num_eval_gates: {}\n  stream_len: {}\n  commitment: {:?}",
                order.file_stem(),
                circuit.num_inputs,
                circuit.num_eval_gates,
                circuit.stream_len,
                circuit_commitment.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>(),
            ));
        }

        let actual_leaves = super::ACE_CIRCUIT_REGISTRY_LEAVES.map(Word::new);
        assert_eq!(
            actual_leaves.as_slice(),
            expected_leaves.as_slice(),
            "ACE_CIRCUIT_REGISTRY_LEAVES in config.rs is stale. Regenerate with: {REGEN_HINT}",
        );

        let tree = super::ace_circuit_registry_tree();
        let expected: Vec<u64> = tree.root().iter().map(Felt::as_canonical_u64).collect();

        let snapshot = format!("{}\nrelation_digest: {:?}", snapshot_lines.join("\n"), expected);
        insta::assert_snapshot!(snapshot);

        let actual: Vec<u64> = super::RELATION_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, expected,
            "RELATION_DIGEST in config.rs is stale. Regenerate with: {REGEN_HINT}"
        );
    }

    fn padding_leaf(index: usize) -> Word {
        Eidos::hash_elements(&[
            Felt::new_unchecked(ACE_REGISTRY_PADDING_DOMAIN),
            Felt::new_unchecked(index as u64),
        ])
    }
}
