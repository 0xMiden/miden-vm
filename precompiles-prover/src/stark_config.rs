//! STARK configuration for proving/verifying custom chiplet AIRs.
//!
//! This module provides both:
//! - production-style configuration factories matching the Miden VM hash-function surface and
//!   PCS/security parameters; and
//! - the legacy fast Poseidon2 test configuration used by local examples/tests.
//!
//! Production configs delegate to `miden_air::config` and bind
//! [`PRECOMPILE_RELATION_DIGEST`]. Callers should observe protocol parameters with
//! [`observe_protocol_params`] before proving or verifying.

pub use miden_air::config::{
    Blake3Config, KeccakConfig, Poseidon2Config, RelationDigest, RpoConfig, RpxConfig,
    observe_protocol_params, pcs_params,
};
use miden_core::Felt;
use miden_crypto::{
    field::Field,
    hash::poseidon2::Poseidon2Permutation256,
    stark::{
        GenericStarkConfig, challenger::DuplexChallenger, dft::Radix2DitParallel,
        hasher::StatefulSponge, lmcs::config::LmcsConfig, pcs::PcsParams,
        symmetric::TruncatedPermutation,
    },
};

// SHARED TYPES
// ================================================================================================

/// Precompile prover STARK configuration with pre-filled common type parameters.
pub type PrecompileStarkConfig<L, Ch> = miden_air::config::MidenStarkConfig<L, Ch>;

/// Packed field type for SIMD.
pub type PackedFelt = <Felt as Field>::Packing;

/// Number of inputs to the Merkle compression function.
const COMPRESSION_INPUTS: usize = 2;

// DOMAIN-SEPARATED FIAT-SHAMIR TRANSCRIPT
// ================================================================================================

/// Placeholder relation digest for the precompile chiplet AIR set.
///
/// The VM binds `RELATION_DIGEST = Poseidon2::hash_elements([PROTOCOL_ID,
/// CIRCUIT_COMMITMENT])`. The precompile prover does not yet have a generated
/// relation/circuit commitment, so for the serialized-proof surface we bind an
/// explicit empty placeholder digest, `[Felt::ZERO; 4]`, instead of reusing the
/// VM digest. Replace this with the generated precompile relation digest before
/// treating proofs as production-secure across AIR upgrades.
pub const PRECOMPILE_RELATION_DIGEST: RelationDigest = [Felt::ZERO; 4];

/// Default hash function for compatibility APIs such as
/// [`SessionTraces::prove`](crate::session::SessionTraces::prove).
pub const DEFAULT_HASH_FUNCTION: miden_core::proof::HashFunction =
    miden_core::proof::HashFunction::Poseidon2;

// PRODUCTION HASH CONFIGS
// ================================================================================================

/// Creates an RPO-based STARK configuration.
pub fn rpo_config(params: PcsParams) -> RpoConfig {
    miden_air::config::rpo_config_with_relation_digest(params, PRECOMPILE_RELATION_DIGEST)
}

/// Creates a Poseidon2-based STARK configuration.
pub fn poseidon2_config(params: PcsParams) -> Poseidon2Config {
    miden_air::config::poseidon2_config_with_relation_digest(params, PRECOMPILE_RELATION_DIGEST)
}

/// Creates an RPX-based STARK configuration.
pub fn rpx_config(params: PcsParams) -> RpxConfig {
    miden_air::config::rpx_config_with_relation_digest(params, PRECOMPILE_RELATION_DIGEST)
}

/// Creates a Blake3_256-based STARK configuration.
pub fn blake3_256_config(params: PcsParams) -> Blake3Config {
    miden_air::config::blake3_256_config_with_relation_digest(params, PRECOMPILE_RELATION_DIGEST)
}

/// Creates a Keccak-based STARK configuration.
pub fn keccak_config(params: PcsParams) -> KeccakConfig {
    miden_air::config::keccak_config_with_relation_digest(params, PRECOMPILE_RELATION_DIGEST)
}

// LEGACY TEST CONFIG
// ================================================================================================

/// Sponge state width in field elements.
const WIDTH: usize = 12;
/// Sponge rate (absorbable elements per permutation).
const RATE: usize = 8;
/// Sponge digest width in field elements.
const DIGEST: usize = 4;

/// Poseidon2 permutation type.
pub type Perm = Poseidon2Permutation256;

/// Stateful sponge for LMCS hashing.
pub type Sponge = StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Compression function for Merkle tree construction.
pub type Compress = TruncatedPermutation<Perm, COMPRESSION_INPUTS, DIGEST, WIDTH>;

/// Duplex challenger for Fiat-Shamir.
pub type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Algebraic LMCS for the Poseidon2 test/default config.
type AlgLmcs<P> = LmcsConfig<
    PackedFelt,
    PackedFelt,
    StatefulSponge<P, WIDTH, RATE, DIGEST>,
    TruncatedPermutation<P, COMPRESSION_INPUTS, DIGEST, WIDTH>,
    WIDTH,
    DIGEST,
>;

/// LMCS configuration for the Poseidon2 test/default config.
pub type Lmcs = AlgLmcs<Perm>;

/// DFT implementation.
pub type Dft = Radix2DitParallel<Felt>;

/// Full legacy test STARK configuration type.
pub type TestConfig = Poseidon2Config;

/// Test PCS parameters (fast but insecure — for testing only).
///
/// Uses small values to keep proofs small and proving fast:
/// - log_blowup: 3 (blowup = 8, supports degree-8 constraints)
/// - log_folding_arity: 1 (arity = 2)
/// - log_final_degree: 3 (final poly = 8)
/// - num_queries: 4
pub fn test_pcs_params() -> PcsParams {
    PcsParams::new(
        3, // log_blowup (must be >= log_quotient_degree)
        1, // log_folding_arity
        3, // log_final_degree
        0, // folding_pow_bits
        0, // deep_pow_bits
        4, // num_queries
        0, // query_pow_bits
    )
    .expect("invalid test PCS params")
}

/// Create a fresh challenger for proving/verification under the legacy test
/// config.
pub fn test_challenger() -> Challenger {
    DuplexChallenger::new(Poseidon2Permutation256)
}

/// Create the LMCS instance for the legacy test config.
pub fn test_lmcs() -> Lmcs {
    LmcsConfig::new(Sponge::new(Poseidon2Permutation256), Compress::new(Poseidon2Permutation256))
}

/// Create the full legacy test STARK configuration.
pub fn test_config() -> TestConfig {
    GenericStarkConfig::new(test_pcs_params(), test_lmcs(), Dft::default(), test_challenger())
}
