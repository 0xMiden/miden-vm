//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_crypto::stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::vec;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::Field,
    hash::{
        blake::Blake3Hasher,
        keccak::{Keccak256Hash, KeccakF, VECTOR_LEN},
        poseidon2::Poseidon2Permutation256,
        rpo::RpoPermutation256,
        rpx::RpxPermutation256,
    },
    stark::{
        GenericStarkConfig,
        challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64},
        dft::Radix2DitParallel,
        fri::PcsParams,
        hasher::{ChainingHasher, SerializingStatefulSponge, StatefulSponge},
        lmcs::LmcsConfig,
        symmetric::{
            CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge,
            TruncatedPermutation,
        },
    },
};

// SHARED
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
const LOG_FOLDING_ARITY: u8 = 2;
/// Log2 of the final polynomial degree (degree = 128).
const LOG_FINAL_DEGREE: u8 = 7;
/// Proof-of-work bits for FRI folding challenges.
const FOLDING_POW_BITS: usize = 16;
/// Proof-of-work bits for DEEP composition polynomial.
const DEEP_POW_BITS: usize = 0;
/// Number of FRI query repetitions.
const NUM_QUERIES: usize = 27;
/// Proof-of-work bits for query phase.
const QUERY_POW_BITS: usize = 0;

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
    let challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
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
    let challenger = SerializingChallenger64::from_hasher(vec![], Keccak256Hash {});
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

// ALGEBRAIC HASHES (RPO, Poseidon2, RPX)
// ================================================================================================

/// Sponge state width in field elements.
const SPONGE_WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const SPONGE_RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST_WIDTH: usize = 4;

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
fn alg_config<P>(params: PcsParams, perm: P) -> MidenStarkConfig<AlgLmcs<P>, AlgChallenger<P>>
where
    P: CryptographicPermutation<[Felt; SPONGE_WIDTH]> + Copy,
{
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}
