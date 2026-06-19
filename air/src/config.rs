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
    Felt::new_unchecked(13902732461197489073),
    Felt::new_unchecked(6888932983199554608),
    Felt::new_unchecked(8977543948613743056),
    Felt::new_unchecked(15805306244985801009),
];

/// Depth of the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = 5;

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [
    [
        Felt::new_unchecked(3284838478586860231),
        Felt::new_unchecked(8232327716635689983),
        Felt::new_unchecked(14492474651656057973),
        Felt::new_unchecked(3617571028416963960),
    ],
    [
        Felt::new_unchecked(14999470832778431774),
        Felt::new_unchecked(16338692871960670055),
        Felt::new_unchecked(7486166740348511793),
        Felt::new_unchecked(7968169965125511279),
    ],
    [
        Felt::new_unchecked(17626942931138273661),
        Felt::new_unchecked(9641969350857076660),
        Felt::new_unchecked(3726361883488520174),
        Felt::new_unchecked(12167571597253502546),
    ],
    [
        Felt::new_unchecked(16764146759572462378),
        Felt::new_unchecked(8835548805675777424),
        Felt::new_unchecked(12098980756995274780),
        Felt::new_unchecked(5710208936271153852),
    ],
    [
        Felt::new_unchecked(11172305658942209659),
        Felt::new_unchecked(16750643941991940918),
        Felt::new_unchecked(737183258017013874),
        Felt::new_unchecked(11265667129682603802),
    ],
    [
        Felt::new_unchecked(5634965743159046719),
        Felt::new_unchecked(12396116446558257450),
        Felt::new_unchecked(17221241174698218516),
        Felt::new_unchecked(16906240663064599987),
    ],
    [
        Felt::new_unchecked(5747323512867845891),
        Felt::new_unchecked(7696311494306557210),
        Felt::new_unchecked(9601531929971738781),
        Felt::new_unchecked(7880928119084984071),
    ],
    [
        Felt::new_unchecked(5220442492693135099),
        Felt::new_unchecked(161882851065045101),
        Felt::new_unchecked(2227773874899443479),
        Felt::new_unchecked(719229046909750173),
    ],
    [
        Felt::new_unchecked(12192842105620037190),
        Felt::new_unchecked(4051954424589187278),
        Felt::new_unchecked(15824699122862223817),
        Felt::new_unchecked(14292937904266885453),
    ],
    [
        Felt::new_unchecked(1986270238447846979),
        Felt::new_unchecked(8058692629402128367),
        Felt::new_unchecked(11734397551617350333),
        Felt::new_unchecked(471133004851934002),
    ],
    [
        Felt::new_unchecked(18058471820018850982),
        Felt::new_unchecked(14008620573591798061),
        Felt::new_unchecked(5482659571790487915),
        Felt::new_unchecked(11478335926312559286),
    ],
    [
        Felt::new_unchecked(11559798179723589656),
        Felt::new_unchecked(9793832407932460582),
        Felt::new_unchecked(6599593512639147462),
        Felt::new_unchecked(5387203255119893723),
    ],
    [
        Felt::new_unchecked(7616237007768146399),
        Felt::new_unchecked(10162089181177310913),
        Felt::new_unchecked(10037674794776672928),
        Felt::new_unchecked(13049712342733755804),
    ],
    [
        Felt::new_unchecked(4245163160822647077),
        Felt::new_unchecked(14698926430022299808),
        Felt::new_unchecked(5809998870772720246),
        Felt::new_unchecked(1818335536045579315),
    ],
    [
        Felt::new_unchecked(12670406199081729387),
        Felt::new_unchecked(4263198030977457197),
        Felt::new_unchecked(7085457351823891439),
        Felt::new_unchecked(11236915207535375980),
    ],
    [
        Felt::new_unchecked(12210663953284959782),
        Felt::new_unchecked(17432933388776690194),
        Felt::new_unchecked(1541199398698269878),
        Felt::new_unchecked(2701915002594721111),
    ],
    [
        Felt::new_unchecked(3965138373977168769),
        Felt::new_unchecked(17686745238937450626),
        Felt::new_unchecked(17497267036209737666),
        Felt::new_unchecked(2907279949022015269),
    ],
    [
        Felt::new_unchecked(8181151974637978326),
        Felt::new_unchecked(12625716703926527934),
        Felt::new_unchecked(17699584242582462297),
        Felt::new_unchecked(6013882103569589367),
    ],
    [
        Felt::new_unchecked(4700760021765627407),
        Felt::new_unchecked(15407164875925528530),
        Felt::new_unchecked(1124895392189103001),
        Felt::new_unchecked(16866460596100722944),
    ],
    [
        Felt::new_unchecked(18008074142451515375),
        Felt::new_unchecked(17406631712111833234),
        Felt::new_unchecked(2638119604550440017),
        Felt::new_unchecked(12597437237086773778),
    ],
    [
        Felt::new_unchecked(2569358352645593853),
        Felt::new_unchecked(17137246889451027791),
        Felt::new_unchecked(17699542830564869176),
        Felt::new_unchecked(8966001766339937364),
    ],
    [
        Felt::new_unchecked(18174578201305493398),
        Felt::new_unchecked(17606000125734894409),
        Felt::new_unchecked(14278237781914845653),
        Felt::new_unchecked(15270738840942168065),
    ],
    [
        Felt::new_unchecked(15913438484969350600),
        Felt::new_unchecked(7247248616757736971),
        Felt::new_unchecked(5183523852640584742),
        Felt::new_unchecked(12981604196870114509),
    ],
    [
        Felt::new_unchecked(1146450102480005663),
        Felt::new_unchecked(6683586138477005238),
        Felt::new_unchecked(8690626808590712322),
        Felt::new_unchecked(13529136462229423300),
    ],
    [
        Felt::new_unchecked(11810973834778922440),
        Felt::new_unchecked(5250568469645662070),
        Felt::new_unchecked(9787443739313767292),
        Felt::new_unchecked(9671428178736409324),
    ],
    [
        Felt::new_unchecked(972644671887590687),
        Felt::new_unchecked(17155193287405347174),
        Felt::new_unchecked(17100837627882803655),
        Felt::new_unchecked(1028745544576685688),
    ],
    [
        Felt::new_unchecked(5111666926196967393),
        Felt::new_unchecked(16275414608277139417),
        Felt::new_unchecked(4695595850659629073),
        Felt::new_unchecked(18091914654705348573),
    ],
    [
        Felt::new_unchecked(14733471853743235410),
        Felt::new_unchecked(6782200230054194555),
        Felt::new_unchecked(16523527177486210036),
        Felt::new_unchecked(4281879727854353812),
    ],
    [
        Felt::new_unchecked(17207014957918407683),
        Felt::new_unchecked(8834060820680077792),
        Felt::new_unchecked(5854869878886389405),
        Felt::new_unchecked(6351595286782511821),
    ],
    [
        Felt::new_unchecked(232005496103574022),
        Felt::new_unchecked(5203544264213209162),
        Felt::new_unchecked(1298467938435542237),
        Felt::new_unchecked(8612075082381358233),
    ],
    [
        Felt::new_unchecked(18068815352134764716),
        Felt::new_unchecked(1350794720558374133),
        Felt::new_unchecked(14292349550702212581),
        Felt::new_unchecked(5230104331780646564),
    ],
    [
        Felt::new_unchecked(13592028555441501386),
        Felt::new_unchecked(11550175270520913966),
        Felt::new_unchecked(14659259737343724431),
        Felt::new_unchecked(7194339879025846330),
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
