//! Shared STARK configuration factories, parameterized by the caller's relation identity.
//!
//! Accepted relation/circuit/setup pins belong to the production AIR artifact owner.

use alloc::vec;

use miden_core::{Felt, Word, field::QuadFelt, program::domain::STARK_TRANSCRIPT};
use miden_crypto::{
    field::Field,
    hash::{
        blake::Blake3Hasher,
        eidos::{Eidos, EidosLmcsCompressor, EidosLmcsHasher, MidenEidosChallenger, PACKED_LANES},
        keccak::{Keccak256Hash, KeccakF, VECTOR_LEN},
        poseidon2::Poseidon2Permutation256,
        rpo::RpoPermutation256,
        rpx::RpxPermutation256,
    },
};

pub use crate::{GenericStarkConfig, StarkConfig};
use crate::{
    challenger::{CanObserve, DuplexChallenger, HashChallenger, SerializingChallenger64},
    dft::Radix2DitParallel,
    hasher::{ChainingHasher, SerializingStatefulSponge, StatefulSponge},
    lmcs::config::LmcsConfig,
    pcs::PcsParams,
    symmetric::{
        CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge,
        TruncatedPermutation,
    },
};

/// Eidos commitment configuration; the hash primitives remain crypto-owned.
pub type EidosLmcs = LmcsConfig<
    [Felt; PACKED_LANES],
    [u64; PACKED_LANES],
    EidosLmcsHasher,
    EidosLmcsCompressor,
    4,
    4,
>;

/// Creates the Eidos LMCS configuration used by canonical STARK configurations.
pub const fn lmcs_config() -> EidosLmcs {
    LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor)
}

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

/// Relation digest absorbed into the Fiat-Shamir transcript domain separator.
pub type RelationDigest = [Felt; 4];

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
    // Batch 1: PCS parameters, zero-padded to SPONGE_RATE.
    challenger.observe(Felt::new_unchecked(params.num_queries() as u64));
    challenger.observe(Felt::new_unchecked(params.query_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.deep_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.folding_pow_bits() as u64));
    challenger.observe(Felt::new_unchecked(params.log_blowup() as u64));
    challenger.observe(Felt::new_unchecked(params.log_final_degree() as u64));
    challenger.observe(Felt::new_unchecked(1_u64 << params.log_folding_arity()));
    challenger.observe(Felt::ZERO);
}

// ALGEBRAIC HASHES (RPO, Poseidon2, RPX)
// ================================================================================================

/// Sponge state width in field elements.
const SPONGE_WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
pub const SPONGE_RATE: usize = 8;
/// Sponge digest width in field elements.
pub const DIGEST_WIDTH: usize = 4;
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

// EIDOS
// ================================================================================================

/// Concrete STARK configuration type for Eidos.
pub type EidosConfig = MidenStarkConfig<EidosLmcs, MidenEidosChallenger>;

/// Creates an Eidos-based STARK configuration bound to `relation_digest`.
pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
    let lmcs = lmcs_config();
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
