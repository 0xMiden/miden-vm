//! Shared Miden-field STARK configurations and transcript initialization.
//!
//! Factories bind a caller-supplied relation digest. Eidos additionally takes the caller's typed
//! transcript domain so relation packages retain ownership of their protocol domains.

use alloc::vec;

use miden_crypto::{
    Felt, Word,
    field::BinomialExtensionField,
    hash::{
        blake::Blake3Hasher,
        eidos::{Eidos, EidosDomain, MidenEidosChallenger, Transcript},
        keccak::{Keccak256Hash, KeccakF, VECTOR_LEN},
        stateful::{ChainingHasher, SerializingStatefulSponge, StatefulSponge},
    },
};
use p3_challenger::{CanObserve, HashChallenger, SerializingChallenger64};
use p3_dft::Radix2DitParallel;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge};

use super::{EidosLmcs, GenericStarkConfig, lmcs_config};
use crate::{lmcs::config::LmcsConfig, pcs::PcsParams};

// SHARED TYPES
// ================================================================================================

/// Miden-field STARK configuration with pre-filled common type parameters.
///
/// All Miden configurations use `Felt` as the base field, its quadratic extension,
/// and `Radix2DitParallel<Felt>` as the DFT. Only the LMCS commitment scheme (`L`) and
/// Fiat-Shamir challenger (`Ch`) vary by hash function.
pub type MidenStarkConfig<L, Ch> =
    GenericStarkConfig<Felt, BinomialExtensionField<Felt, 2>, L, Radix2DitParallel<Felt>, Ch>;

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

/// Creates an Eidos-based STARK configuration bound to `relation_digest` and `domain`.
///
/// The caller owns the transcript domain and supplies its registered, typed value.
pub fn eidos_config(
    params: PcsParams,
    relation_digest: RelationDigest,
    domain: impl EidosDomain<Encoding = Transcript>,
) -> EidosConfig {
    let lmcs = lmcs_config();
    let transcript_init_cv = Eidos::transcript_init_cv(domain);
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
