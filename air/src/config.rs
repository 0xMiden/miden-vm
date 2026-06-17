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

/// Root of the ACE circuit registry accepted by the recursive verifier.
///
/// Active leaves are order-specific ACE circuit commitments indexed by `ProofOrder::tag()`.
/// This root is absorbed into Fiat-Shamir as the recursive relation identifier. The recursive
/// advice builder also seeds the corresponding tree.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
pub const RELATION_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(2510026394581042689),
    Felt::new_unchecked(5394882770041513920),
    Felt::new_unchecked(7244246892549217641),
    Felt::new_unchecked(4733287224461634308),
];

/// Depth of the ACE circuit registry tree.
pub const ACE_CIRCUIT_REGISTRY_DEPTH: usize = 5;

/// Leaves in the ACE circuit registry tree.
///
/// Active leaves are order-specific ACE circuit commitments indexed by `ProofOrder::tag()`.
/// Inactive leaves are deterministic padding.
pub const ACE_CIRCUIT_REGISTRY_LEAVES: [[Felt; 4]; 1 << ACE_CIRCUIT_REGISTRY_DEPTH] = [
    [
        Felt::new_unchecked(24783171865739857),
        Felt::new_unchecked(7127553265361334048),
        Felt::new_unchecked(3897334861478314898),
        Felt::new_unchecked(6313249570395089577),
    ],
    [
        Felt::new_unchecked(4987354328664649769),
        Felt::new_unchecked(7459591106023001916),
        Felt::new_unchecked(1803738333602139636),
        Felt::new_unchecked(5533595785845610778),
    ],
    [
        Felt::new_unchecked(4560213744455813332),
        Felt::new_unchecked(2516539659880451217),
        Felt::new_unchecked(7295353875824411556),
        Felt::new_unchecked(6823967295387362732),
    ],
    [
        Felt::new_unchecked(9068359012062704689),
        Felt::new_unchecked(4375400920796157652),
        Felt::new_unchecked(4752807284711163154),
        Felt::new_unchecked(6545185574479929215),
    ],
    [
        Felt::new_unchecked(1940058479946711481),
        Felt::new_unchecked(1824788694997684264),
        Felt::new_unchecked(3826113870241805208),
        Felt::new_unchecked(6189194500583241759),
    ],
    [
        Felt::new_unchecked(5376296098277867667),
        Felt::new_unchecked(2279247683192561201),
        Felt::new_unchecked(4165339443840289077),
        Felt::new_unchecked(5953199880825682748),
    ],
    [
        Felt::new_unchecked(670174752197946447),
        Felt::new_unchecked(8777273628572171981),
        Felt::new_unchecked(3182135647718276022),
        Felt::new_unchecked(6500380144083189635),
    ],
    [
        Felt::new_unchecked(5688202359777958495),
        Felt::new_unchecked(8950320572981376836),
        Felt::new_unchecked(169295229138000877),
        Felt::new_unchecked(813683314524007896),
    ],
    [
        Felt::new_unchecked(7459022767144147087),
        Felt::new_unchecked(1284507349382510269),
        Felt::new_unchecked(2913010915955959351),
        Felt::new_unchecked(7688816131515155717),
    ],
    [
        Felt::new_unchecked(5876459623316323053),
        Felt::new_unchecked(6478672378196721431),
        Felt::new_unchecked(4860158924472234562),
        Felt::new_unchecked(7844170213133680083),
    ],
    [
        Felt::new_unchecked(1462974323255506686),
        Felt::new_unchecked(4764297051194385386),
        Felt::new_unchecked(8058475597577822155),
        Felt::new_unchecked(6430736171429724940),
    ],
    [
        Felt::new_unchecked(2627201360353621778),
        Felt::new_unchecked(7329292033977909963),
        Felt::new_unchecked(7945871357391416908),
        Felt::new_unchecked(8192894564389532598),
    ],
    [
        Felt::new_unchecked(444071982357061604),
        Felt::new_unchecked(1507421276840253337),
        Felt::new_unchecked(2445227410041689601),
        Felt::new_unchecked(2077807362638314557),
    ],
    [
        Felt::new_unchecked(2115271293535918628),
        Felt::new_unchecked(2672558495035767491),
        Felt::new_unchecked(2173296295116527099),
        Felt::new_unchecked(2602413378715255737),
    ],
    [
        Felt::new_unchecked(8855646018226049523),
        Felt::new_unchecked(2620492606346593023),
        Felt::new_unchecked(3369264810658607833),
        Felt::new_unchecked(7827380711855103607),
    ],
    [
        Felt::new_unchecked(3559749311310619785),
        Felt::new_unchecked(8797888172761233653),
        Felt::new_unchecked(2283075626316096186),
        Felt::new_unchecked(2076776437459269287),
    ],
    [
        Felt::new_unchecked(1831532800345224520),
        Felt::new_unchecked(4139000888622613552),
        Felt::new_unchecked(3770742239376038027),
        Felt::new_unchecked(3355700179076123135),
    ],
    [
        Felt::new_unchecked(7586160116672304370),
        Felt::new_unchecked(819131209041478454),
        Felt::new_unchecked(6526679717919125309),
        Felt::new_unchecked(6873345247549161101),
    ],
    [
        Felt::new_unchecked(6409917364437054035),
        Felt::new_unchecked(5615404520408491724),
        Felt::new_unchecked(8926533714486737478),
        Felt::new_unchecked(9199994691999453020),
    ],
    [
        Felt::new_unchecked(7057347802672919026),
        Felt::new_unchecked(1556162801603290262),
        Felt::new_unchecked(381398572779282273),
        Felt::new_unchecked(8532226683583302727),
    ],
    [
        Felt::new_unchecked(7870317909490551631),
        Felt::new_unchecked(5241698646483758846),
        Felt::new_unchecked(7796460540832491111),
        Felt::new_unchecked(3214945569031738465),
    ],
    [
        Felt::new_unchecked(7396030441601927045),
        Felt::new_unchecked(5230264052281969776),
        Felt::new_unchecked(1693747729902269158),
        Felt::new_unchecked(6451164568584936718),
    ],
    [
        Felt::new_unchecked(8888891091737108966),
        Felt::new_unchecked(2027989918597121137),
        Felt::new_unchecked(3020926807366775306),
        Felt::new_unchecked(2961979088400517537),
    ],
    [
        Felt::new_unchecked(5360769381928880853),
        Felt::new_unchecked(5637637519408356149),
        Felt::new_unchecked(9133415409598736497),
        Felt::new_unchecked(102911608469655880),
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

    use miden_ace_codegen::{AceConfig, LayoutKind};
    use miden_core::{Felt, field::QuadFelt};
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
        let config = AceConfig {
            num_quotient_chunks: 8,
            num_vlpi_groups: 1,
            layout: LayoutKind::Masm,
            is_multi_air: true,
        };
        let mut expected_leaves = (0..super::ACE_CIRCUIT_REGISTRY_LEAVES.len())
            .map(padding_leaf)
            .collect::<Vec<_>>();
        let mut snapshot_lines = Vec::new();
        let mut expected_metadata = None;

        for order in ProofOrder::variants() {
            let circuit =
                ace::build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &order).unwrap();
            let encoded = circuit.to_ace().unwrap();
            let circuit_digest = Eidos::hash_elements(encoded.instructions());
            let circuit_commitment =
                [circuit_digest[0], circuit_digest[1], circuit_digest[2], circuit_digest[3]];
            let stream_len = encoded.instructions().len();
            let metadata = (encoded.num_vars(), encoded.num_eval_rows(), stream_len);
            if let Some(expected) = expected_metadata {
                assert_eq!(metadata, expected, "ACE circuit metadata must be uniform");
            } else {
                expected_metadata = Some(metadata);
            }

            let tag = order.tag() as usize;
            assert!(tag < ProofOrder::variants().len(), "invalid proof-order tag");
            expected_leaves[tag] = Word::new(circuit_commitment);

            snapshot_lines.push(format!(
                "{}:\n  num_inputs: {}\n  num_eval_gates: {}\n  stream_len: {}\n  commitment: {:?}",
                order.file_stem(),
                encoded.num_vars(),
                encoded.num_eval_rows(),
                stream_len,
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
