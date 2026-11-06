//! PVM STARK configuration.
//!
//! The Eidos factory supplies the PVM transcript domain. Generic factories and transcript
//! observation live in [`miden_stark::config`]; immutable PCS policy lives in
//! [`miden_air::precompiles::policy`].

use miden_core::{Felt, program::domain::STARK_TRANSCRIPT};
#[cfg(all(test, feature = "prover"))]
use miden_crypto::hash::eidos::MidenEidosChallenger;
#[cfg(all(test, feature = "prover"))]
use miden_stark::StarkConfig;
pub use miden_stark::{
    config::{EidosConfig, RelationDigest},
    pcs::PcsParams,
};

/// Relation digest binding the canonical PVM ACE circuit into the Fiat-Shamir transcript.
///
/// The accepted value is pinned in [`miden_air::precompiles::protocol::PINS`].
pub(crate) const PRECOMPILE_RELATION_DIGEST: RelationDigest = {
    let [d0, d1, d2, d3] = miden_air::precompiles::PVM_RELATION_DIGEST;
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

/// Creates the Eidos configuration with the PVM transcript domain.
pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
    miden_stark::config::eidos_config(params, relation_digest, STARK_TRANSCRIPT)
}

// TEST CONFIG
// ================================================================================================

/// Eidos STARK configuration with reduced PCS parameters for tests.
#[cfg(all(test, feature = "prover"))]
pub(crate) type TestConfig = EidosConfig;

/// Test PCS parameters (fast but insecure — for testing only).
///
/// Uses small values to keep proofs small and proving fast:
/// - log_blowup: 3 (blowup = 8, permits up to eight quotient chunks)
/// - log_folding_arity: 1 (arity = 2)
/// - log_final_degree: 3 (final poly = 8)
/// - num_queries: 4
#[cfg(all(test, feature = "prover"))]
pub(crate) fn test_pcs_params() -> PcsParams {
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
#[cfg(all(test, feature = "prover"))]
pub(crate) fn test_challenger() -> MidenEidosChallenger {
    test_config().challenger()
}

/// Creates an Eidos STARK configuration with reduced PCS parameters.
#[cfg(all(test, feature = "prover"))]
pub(crate) fn test_config() -> TestConfig {
    eidos_config(test_pcs_params(), PRECOMPILE_RELATION_DIGEST)
}
