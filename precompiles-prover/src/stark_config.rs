//! STARK configuration for proving/verifying custom chiplet AIRs.
//!
//! This module provides both:
//! - production-style configuration factories matching the Miden VM hash-function surface and
//!   PCS/security parameters; and
//! - the legacy fast Poseidon2 test configuration used by local examples/tests.
//!
//! Production configs delegate to `miden_air::config`; callers pass the relation digest
//! explicitly. Callers should observe protocol parameters with [`observe_protocol_params`]
//! before proving or verifying.

pub use miden_air::config::{
    Blake3Config, KeccakConfig, Poseidon2Config, RelationDigest, RpoConfig, RpxConfig,
    blake3_256_config, keccak_config, observe_protocol_params, poseidon2_config, rpo_config,
    rpx_config,
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

/// Default hash function for compatibility APIs such as
/// [`SessionTraces::prove`](crate::session::SessionTraces::prove).
pub const DEFAULT_HASH_FUNCTION: miden_core::proof::HashFunction =
    miden_core::proof::HashFunction::Poseidon2;

// PRECOMPILE PCS PARAMETERS
// ================================================================================================

/// PCS parameters for the precompile chiplet stack.
///
/// Every chiplet AIR in [`ChipletAir`](crate::session::ChipletAir) closes at
/// `log_quotient_degree <= 2` (see the `log_quotient_degrees_fit_the_blowup` test), so
/// the stack only needs `log_blowup = 2` (blowup = 4), unlike the core VM's
/// `miden_air::config::pcs_params`, which is fixed at `log_blowup = 3` for its own
/// degree-8 constraints.
///
/// The remaining FRI parameters (folding arity, final degree, PoW bits, query count)
/// mirror `miden_air::config::pcs_params` as-is; they have not been independently
/// re-derived for this lower blowup and should get a dedicated security review before
/// this config is relied on outside benchmarking.
pub fn precompile_pcs_params() -> PcsParams {
    PcsParams::new(
        3,  // log_blowup (must be >= log_quotient_degree)
        2,  // log_folding_arity
        7,  // log_final_degree
        4,  // folding_pow_bits
        12, // deep_pow_bits
        27, // num_queries
        16, // query_pow_bits
    )
    .expect("invalid precompile PCS parameters")
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
