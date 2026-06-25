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
    Felt::new_unchecked(3663131485924157257),
    Felt::new_unchecked(3956414906926947112),
    Felt::new_unchecked(258202875783084993),
    Felt::new_unchecked(3614315938832407169),
];

/// Depth of the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = 5;

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [
    [
        Felt::new_unchecked(5990543205732029852),
        Felt::new_unchecked(2175786501623562911),
        Felt::new_unchecked(3819432717512085025),
        Felt::new_unchecked(4712886610692902078),
    ],
    [
        Felt::new_unchecked(1453209352659225810),
        Felt::new_unchecked(9156176651446986572),
        Felt::new_unchecked(2154781782250440413),
        Felt::new_unchecked(6933336150617262813),
    ],
    [
        Felt::new_unchecked(2987038477784436690),
        Felt::new_unchecked(4377069677099665111),
        Felt::new_unchecked(5362456232227310548),
        Felt::new_unchecked(5619399957725557028),
    ],
    [
        Felt::new_unchecked(6980062061665809167),
        Felt::new_unchecked(2822965247518731033),
        Felt::new_unchecked(2953800096617233610),
        Felt::new_unchecked(909747268499555440),
    ],
    [
        Felt::new_unchecked(8742372746025268129),
        Felt::new_unchecked(6456812370784059583),
        Felt::new_unchecked(2881961331579849215),
        Felt::new_unchecked(2697090673462826081),
    ],
    [
        Felt::new_unchecked(5880158574422165582),
        Felt::new_unchecked(275245293257594945),
        Felt::new_unchecked(6777613432073713712),
        Felt::new_unchecked(5071686250619540904),
    ],
    [
        Felt::new_unchecked(483054772623143895),
        Felt::new_unchecked(5512625559218867338),
        Felt::new_unchecked(9056743736315697641),
        Felt::new_unchecked(461992869925512666),
    ],
    [
        Felt::new_unchecked(5039966377256783409),
        Felt::new_unchecked(1736052511009326904),
        Felt::new_unchecked(4759576196235619066),
        Felt::new_unchecked(5646789277853002349),
    ],
    [
        Felt::new_unchecked(1526052867248309864),
        Felt::new_unchecked(7339273242616075647),
        Felt::new_unchecked(8511538418463339886),
        Felt::new_unchecked(5722975569714531232),
    ],
    [
        Felt::new_unchecked(7459636512443533616),
        Felt::new_unchecked(8600966667762035114),
        Felt::new_unchecked(4529943533909486643),
        Felt::new_unchecked(3531158330958409727),
    ],
    [
        Felt::new_unchecked(8135619871260143751),
        Felt::new_unchecked(5635129449263984045),
        Felt::new_unchecked(8217280830988731995),
        Felt::new_unchecked(6683042552619461402),
    ],
    [
        Felt::new_unchecked(4735619659838954636),
        Felt::new_unchecked(4773380894938786533),
        Felt::new_unchecked(6866103694765028429),
        Felt::new_unchecked(6295345520352730094),
    ],
    [
        Felt::new_unchecked(4307163597437700802),
        Felt::new_unchecked(1412283589615458408),
        Felt::new_unchecked(6340942288780670345),
        Felt::new_unchecked(1868956094278723960),
    ],
    [
        Felt::new_unchecked(4694169555447113248),
        Felt::new_unchecked(3720586270476738147),
        Felt::new_unchecked(2989891113308633765),
        Felt::new_unchecked(7039332867724787303),
    ],
    [
        Felt::new_unchecked(2837890232593556893),
        Felt::new_unchecked(6765777817069906881),
        Felt::new_unchecked(7405585097212160016),
        Felt::new_unchecked(6418556030517405120),
    ],
    [
        Felt::new_unchecked(3670613717657559929),
        Felt::new_unchecked(2579050072641489078),
        Felt::new_unchecked(8795610700628953586),
        Felt::new_unchecked(7374032963744733489),
    ],
    [
        Felt::new_unchecked(7731525324855953863),
        Felt::new_unchecked(7185643059368964607),
        Felt::new_unchecked(8143800223853349112),
        Felt::new_unchecked(3483584888444524579),
    ],
    [
        Felt::new_unchecked(8076910736710484649),
        Felt::new_unchecked(5048415048728983420),
        Felt::new_unchecked(6517217577775396329),
        Felt::new_unchecked(8194865857552023119),
    ],
    [
        Felt::new_unchecked(4774484576970881029),
        Felt::new_unchecked(1069157519719486413),
        Felt::new_unchecked(3956424633595688324),
        Felt::new_unchecked(6474478952125370262),
    ],
    [
        Felt::new_unchecked(3305229610874901178),
        Felt::new_unchecked(3819158437284352395),
        Felt::new_unchecked(3311981750272587118),
        Felt::new_unchecked(4712348220171958220),
    ],
    [
        Felt::new_unchecked(8029436117714812681),
        Felt::new_unchecked(482213898197627079),
        Felt::new_unchecked(1457322425062807331),
        Felt::new_unchecked(8184010786374781468),
    ],
    [
        Felt::new_unchecked(2516369381725811393),
        Felt::new_unchecked(8051499271592565050),
        Felt::new_unchecked(5291088768434577885),
        Felt::new_unchecked(8753750822133775857),
    ],
    [
        Felt::new_unchecked(3149561867286646934),
        Felt::new_unchecked(5793236217627618322),
        Felt::new_unchecked(2070317450192955718),
        Felt::new_unchecked(7653053622945705675),
    ],
    [
        Felt::new_unchecked(357106440970696422),
        Felt::new_unchecked(3491830347322667999),
        Felt::new_unchecked(1487596286829164647),
        Felt::new_unchecked(7587597018551710688),
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
