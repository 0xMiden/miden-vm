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
    Felt::new_unchecked(4329388950571137465),
    Felt::new_unchecked(732896042109656416),
    Felt::new_unchecked(2001663974766063116),
    Felt::new_unchecked(4001053491306862303),
];

/// Depth of the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = 5;

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [
    [
        Felt::new_unchecked(6216272059612367972),
        Felt::new_unchecked(1861232080528406120),
        Felt::new_unchecked(6917159948785624751),
        Felt::new_unchecked(3671307780255412746),
    ],
    [
        Felt::new_unchecked(5895529042510967870),
        Felt::new_unchecked(1287191450786096548),
        Felt::new_unchecked(2910290816020975645),
        Felt::new_unchecked(1566620242587536821),
    ],
    [
        Felt::new_unchecked(8560269027747441877),
        Felt::new_unchecked(5387137070451953304),
        Felt::new_unchecked(502406640290644878),
        Felt::new_unchecked(6218375004187872800),
    ],
    [
        Felt::new_unchecked(5007848338997964993),
        Felt::new_unchecked(5289116848714743890),
        Felt::new_unchecked(8248292312851289111),
        Felt::new_unchecked(3872557030302555417),
    ],
    [
        Felt::new_unchecked(8427301895682845876),
        Felt::new_unchecked(8495690352820561368),
        Felt::new_unchecked(5539378788840683407),
        Felt::new_unchecked(8239234871707504661),
    ],
    [
        Felt::new_unchecked(5238125997704506914),
        Felt::new_unchecked(4775994091330747805),
        Felt::new_unchecked(1559744322780365561),
        Felt::new_unchecked(1778037793180920463),
    ],
    [
        Felt::new_unchecked(2152414612925358775),
        Felt::new_unchecked(1749499111612691099),
        Felt::new_unchecked(598357344868648543),
        Felt::new_unchecked(5777797407773663407),
    ],
    [
        Felt::new_unchecked(3344161120031084754),
        Felt::new_unchecked(2194473498957601951),
        Felt::new_unchecked(5917687038289477072),
        Felt::new_unchecked(1612517996523958686),
    ],
    [
        Felt::new_unchecked(2326305294544663153),
        Felt::new_unchecked(4517806241501557613),
        Felt::new_unchecked(3926730438025952014),
        Felt::new_unchecked(8100840954759660319),
    ],
    [
        Felt::new_unchecked(7131365711180576187),
        Felt::new_unchecked(6601640864378631593),
        Felt::new_unchecked(7363945735684870642),
        Felt::new_unchecked(3779529746937207386),
    ],
    [
        Felt::new_unchecked(2785022032174384882),
        Felt::new_unchecked(8975570545938061451),
        Felt::new_unchecked(1994685743168868876),
        Felt::new_unchecked(8012138342556467287),
    ],
    [
        Felt::new_unchecked(4422162874487793975),
        Felt::new_unchecked(625625510772739210),
        Felt::new_unchecked(2009453896034353199),
        Felt::new_unchecked(1590423125657751091),
    ],
    [
        Felt::new_unchecked(8607790180965715768),
        Felt::new_unchecked(894933567760917626),
        Felt::new_unchecked(4901203981245822465),
        Felt::new_unchecked(8463784336976608226),
    ],
    [
        Felt::new_unchecked(6010959130189620447),
        Felt::new_unchecked(4583543169941631465),
        Felt::new_unchecked(9175475990387426714),
        Felt::new_unchecked(7398713925365083828),
    ],
    [
        Felt::new_unchecked(2801722161683306193),
        Felt::new_unchecked(6532535224802959343),
        Felt::new_unchecked(3037773403022666332),
        Felt::new_unchecked(5398927172912498344),
    ],
    [
        Felt::new_unchecked(7235992927112873026),
        Felt::new_unchecked(8653600073923893242),
        Felt::new_unchecked(3377010573312899498),
        Felt::new_unchecked(5118959171626503518),
    ],
    [
        Felt::new_unchecked(8972557174780902250),
        Felt::new_unchecked(2590356085306014211),
        Felt::new_unchecked(4835027655720155538),
        Felt::new_unchecked(3113266462473652816),
    ],
    [
        Felt::new_unchecked(8577378016972951648),
        Felt::new_unchecked(522103715878766563),
        Felt::new_unchecked(2237505198374195088),
        Felt::new_unchecked(5581053212231947895),
    ],
    [
        Felt::new_unchecked(2318340275221360280),
        Felt::new_unchecked(7550651755603306233),
        Felt::new_unchecked(5338207030591251338),
        Felt::new_unchecked(5203330568741166283),
    ],
    [
        Felt::new_unchecked(2399027136734180974),
        Felt::new_unchecked(4075474866642400718),
        Felt::new_unchecked(6955866918450938833),
        Felt::new_unchecked(851378393410665573),
    ],
    [
        Felt::new_unchecked(399311459608907280),
        Felt::new_unchecked(1745917045584903357),
        Felt::new_unchecked(8676659193027152921),
        Felt::new_unchecked(5888334588877195856),
    ],
    [
        Felt::new_unchecked(5474920955514119207),
        Felt::new_unchecked(1363641975323827169),
        Felt::new_unchecked(6590540508242106391),
        Felt::new_unchecked(2892687807092856238),
    ],
    [
        Felt::new_unchecked(5382990625576484106),
        Felt::new_unchecked(4039237534814295771),
        Felt::new_unchecked(3947806847324327803),
        Felt::new_unchecked(6549266133915798594),
    ],
    [
        Felt::new_unchecked(6059208470519915342),
        Felt::new_unchecked(2410166007861365540),
        Felt::new_unchecked(8128799974912845502),
        Felt::new_unchecked(4354912780445044944),
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
