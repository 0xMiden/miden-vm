//! STARK configuration factories for different hash functions.
//!
//! Each factory creates a [`StarkConfig`](miden_crypto::stark::StarkConfig) bundling the
//! PCS parameters, LMCS commitment scheme, and Fiat-Shamir challenger for proving and verification.

use alloc::vec;

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::{
    field::Field,
    hash::{
        blake::Blake3Hasher, keccak::Keccak256Hash, poseidon2::Poseidon2Permutation256,
        rpo::RpoPermutation256, rpx::RpxPermutation256,
    },
    stark::{
        GenericStarkConfig,
        challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64},
        dft::Radix2DitParallel,
        fri::PcsParams,
        hasher::{ChainingHasher, StatefulSponge},
        lmcs::LmcsConfig,
        symmetric::{CompressionFunctionFromHasher, TruncatedPermutation},
    },
};

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

// HASH FUNCTION PARAMETERS
// ================================================================================================

// Byte-oriented hashes (Blake3, Keccak).

/// Digest size in bytes for byte-oriented hashes.
const BYTE_DIGEST_SIZE: usize = 32;
/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// Algebraic hashes (RPO, Poseidon2, RPX).

/// Sponge state width in field elements.
const SPONGE_WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const SPONGE_RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST_WIDTH: usize = 4;

// SHARED TYPE ALIASES
// ================================================================================================

type PackedFelt = <Felt as Field>::Packing;

/// Miden VM STARK configuration with pre-filled common type parameters.
///
/// All Miden configurations use `Felt` as the base field, `QuadFelt` as the extension field,
/// and `Radix2DitParallel<Felt>` as the DFT. Only the LMCS commitment scheme (`L`) and
/// Fiat-Shamir challenger (`Ch`) vary by hash function.
pub type MidenStarkConfig<L, Ch> =
    GenericStarkConfig<Felt, QuadFelt, L, Radix2DitParallel<Felt>, Ch>;

/// Byte-oriented LMCS (for Blake3, Keccak).
type ByteLmcs<H> = LmcsConfig<
    Felt,
    u8,
    ChainingHasher<H>,
    CompressionFunctionFromHasher<H, COMPRESSION_INPUTS, BYTE_DIGEST_SIZE>,
    BYTE_DIGEST_SIZE,
    BYTE_DIGEST_SIZE,
>;

/// Byte-oriented challenger (for Blake3, Keccak).
type ByteChallenger<H> = SerializingChallenger64<Felt, HashChallenger<u8, H, BYTE_DIGEST_SIZE>>;

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

// CONFIGURATION FACTORIES
// ================================================================================================

/// Creates a Blake3_256-based STARK configuration.
pub fn blake3_256_config(
    params: PcsParams,
) -> MidenStarkConfig<ByteLmcs<Blake3Hasher>, ByteChallenger<Blake3Hasher>> {
    let lmcs = LmcsConfig::new(
        ChainingHasher::new(Blake3Hasher),
        CompressionFunctionFromHasher::new(Blake3Hasher),
    );
    let challenger = SerializingChallenger64::from_hasher(vec![], Blake3Hasher);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates a Keccak-based STARK configuration.
pub fn keccak_config(
    params: PcsParams,
) -> MidenStarkConfig<ByteLmcs<Keccak256Hash>, ByteChallenger<Keccak256Hash>> {
    let hash = Keccak256Hash {};
    let lmcs = LmcsConfig::new(ChainingHasher::new(hash), CompressionFunctionFromHasher::new(hash));
    let challenger = SerializingChallenger64::from_hasher(vec![], hash);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates an RPO-based STARK configuration.
pub fn rpo_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpoPermutation256>, AlgChallenger<RpoPermutation256>> {
    let perm = RpoPermutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates a Poseidon2-based STARK configuration.
pub fn poseidon2_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<Poseidon2Permutation256>, AlgChallenger<Poseidon2Permutation256>> {
    let perm = Poseidon2Permutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

/// Creates an RPX-based STARK configuration.
pub fn rpx_config(
    params: PcsParams,
) -> MidenStarkConfig<AlgLmcs<RpxPermutation256>, AlgChallenger<RpxPermutation256>> {
    let perm = RpxPermutation256;
    let lmcs = LmcsConfig::new(StatefulSponge::new(perm), TruncatedPermutation::new(perm));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}
