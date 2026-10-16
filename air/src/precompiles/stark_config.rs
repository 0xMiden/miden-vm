//! STARK configuration for proving/verifying custom chiplet AIRs.
//!
//! This module provides production-style configuration factories matching the Miden VM
//! hash-function surface, along with a smaller Eidos configuration for local tests.
//!
//! Production configs delegate to `crate::shared::config`; callers pass the relation digest
//! explicitly. Callers should observe protocol parameters with [`observe_protocol_params`]
//! before proving or verifying.

use miden_core::Felt;
use miden_crypto::hash::eidos::MidenEidosChallenger;
use miden_lifted_stark::{StarkConfig, pcs::PcsParams};

pub use crate::shared::config::{
    Blake3Config, EidosConfig, KeccakConfig, RelationDigest, blake3_256_config, eidos_config,
    keccak_config, observe_protocol_params,
};

// SHARED TYPES
// ================================================================================================

/// Precompile prover STARK configuration with pre-filled common type parameters.
pub type PrecompileStarkConfig<L, Ch> = crate::shared::config::MidenStarkConfig<L, Ch>;

/// Relation digest binding the canonical PVM ACE circuit into the Fiat-Shamir transcript.
///
/// The generated raw limbs live with the canonical ACE constants; this public field-valued view
/// is the value passed to every production PVM configuration.
pub const PRECOMPILE_RELATION_DIGEST: RelationDigest = {
    let [d0, d1, d2, d3] = crate::precompiles::PVM_RELATION_DIGEST;
    [
        Felt::new_unchecked(d0),
        Felt::new_unchecked(d1),
        Felt::new_unchecked(d2),
        Felt::new_unchecked(d3),
    ]
};

/// Default commitment hash for precompile proofs.
pub const DEFAULT_HASH_FUNCTION: miden_core::proof::HashFunction =
    miden_core::proof::HashFunction::Eidos;

// PRECOMPILE PCS PARAMETERS
// ================================================================================================

/// Log2 of the PVM FRI blowup factor (blowup = 8).
pub(crate) use miden_air_definitions::precompiles::policy::LOG_BLOWUP;
/// Log2 of the PVM FRI folding arity (arity = 4).
pub(crate) use miden_air_definitions::precompiles::policy::LOG_FOLDING_ARITY;
/// PCS parameters for the precompile chiplet stack.
///
/// Mirrors `crate::shared::config::pcs_params` in every parameter, including
/// `log_blowup = 3`. It exists as its own function so the Rust prover and
/// verifier bind the actual PVM parameters into their transcript rather than
/// relying on the core VM's defaults. Every [`ChipletAir`](crate::precompiles::ChipletAir)
/// requires at most four quotient chunks, below the eight permitted by `log_blowup = 3`. The
/// MASM verifier compiles this PCS geometry, so changing it requires a coordinated MASM update
/// and security review; it is not a runtime configuration.
pub use miden_air_definitions::precompiles::policy::precompile_pcs_params;

// TEST CONFIG
// ================================================================================================

/// Eidos STARK configuration with reduced PCS parameters for tests.
pub type TestConfig = EidosConfig;

/// Test PCS parameters (fast but insecure — for testing only).
///
/// Uses small values to keep proofs small and proving fast:
/// - log_blowup: 3 (blowup = 8, permits up to eight quotient chunks)
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

/// Creates a fresh challenger for the Eidos test configuration.
pub fn test_challenger() -> MidenEidosChallenger {
    test_config().challenger()
}

/// Creates an Eidos STARK configuration with reduced PCS parameters.
pub fn test_config() -> TestConfig {
    eidos_config(test_pcs_params(), PRECOMPILE_RELATION_DIGEST)
}
