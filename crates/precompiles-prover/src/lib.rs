#![no_std]
#![allow(
    dead_code,
    unused_imports,
    reason = "the imported prover stack is intentionally retained behind a narrow crate API"
)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

use alloc::string::{String, ToString};

use miden_core::deferred::DeferredState;
pub(crate) use miden_core::proof::MAX_STARK_PROOF_BYTES;
pub use miden_core::{
    deferred::DeferredRoot,
    proof::{HashFunction, StarkProof},
};
pub use session::VerifyError;

/// Default maximum amount of recursive translation work for one deferred root.
///
/// Deferred state is a content-addressed DAG, so its unique-node storage budget does not bound the
/// number or cost of paths that the precompile prover must lower. One work unit represents a node
/// translation or one 32-byte Keccak input chunk. Callers that accept untrusted deferred witnesses
/// should select a limit appropriate for their worker policy with
/// [`prove_deferred_state_with_budget`].
///
/// The default admits the maximum supported merged-root count while rejecting compact DAGs that
/// would expand beyond 65,536 units of translation work.
pub const DEFAULT_MAX_DEFERRED_EXPANSION_WORK: usize = 1 << 16;

/// Hard safety ceiling for recursive deferred translation.
///
/// Translation currently follows truthy, uint, and EC dependencies recursively. Preflight rejects
/// deeper inputs before entering that recursion so untrusted witnesses cannot exhaust the thread
/// stack.
pub const MAX_DEFERRED_TRANSLATION_DEPTH: usize = 256;

#[cfg(any(test, feature = "std"))]
pub(crate) mod ace;
pub(crate) mod ace_registry;
#[cfg(feature = "registry-tools")]
pub mod ace_registry_regen;
pub(crate) mod ec;
pub(crate) mod hash;
pub(crate) mod logup;
#[cfg(feature = "std")]
pub mod masm_verifier;
pub(crate) mod math;
pub(crate) mod primitives;
pub(crate) mod relations;
pub mod security;
pub(crate) mod session;
pub(crate) mod stark_config;
pub(crate) mod transcript;
pub(crate) mod uint;
pub(crate) mod utils;

/// Proves the precompile claims accumulated in `state` against its exact deferred root.
pub fn prove_deferred_state(
    state: &DeferredState,
    hash_fn: HashFunction,
) -> Result<StarkProof, ProveDeferredStateError> {
    prove_deferred_state_with_budget(state, hash_fn, DEFAULT_MAX_DEFERRED_EXPANSION_WORK)
}

/// Proves the precompile claims in `state` while limiting recursive translation expansion.
///
/// Truthy, uint, and EC dependencies are counted with checked arithmetic before session rows are
/// constructed. A shared child is charged once per occurrence in the expanded translation tree,
/// matching the current lowering behavior.
pub fn prove_deferred_state_with_budget(
    state: &DeferredState,
    hash_fn: HashFunction,
    max_expansion_work: usize,
) -> Result<StarkProof, ProveDeferredStateError> {
    let deferred = {
        let _span = tracing::info_span!("build_session").entered();
        deferred::session_from_deferred_state_with_budget(state, max_expansion_work)?
    };
    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        deferred.session.finish(deferred.root)
    };
    Ok(traces.prove_stark(hash_fn)?)
}

/// Verifies a precompile STARK against an explicit deferred root, and returns its conjectured
/// security level in bits.
///
/// The level depends on the proof's largest chiplet trace height, its commitment scheme's column
/// alignment (which varies by hash function), and its PCS parameters, so it is computed from the
/// verified proof rather than fixed by the parameter preset.
pub fn verify_deferred(proof: &StarkProof, public_root: DeferredRoot) -> Result<u32, VerifyError> {
    let (log_max_height, alignment) =
        session::verify_stark(proof, transcript::poseidon2::P2Digest::from(public_root))?;

    Ok(security::conjectured_security_level_for_alignment(
        &stark_config::precompile_pcs_params(),
        log_max_height,
        alignment,
    ))
}

/// Errors produced while proving deferred precompile claims from VM deferred state.
#[derive(Debug, thiserror::Error)]
pub enum ProveDeferredStateError {
    /// The VM deferred DAG could not be translated into the precompile prover's session model.
    #[error("failed to translate deferred state into a precompile proving session: {0}")]
    Translation(String),
    /// The translated precompile session could not be proved.
    #[error(transparent)]
    Prove(#[from] ProveError),
}

impl From<deferred::DeferredSessionError> for ProveDeferredStateError {
    fn from(error: deferred::DeferredSessionError) -> Self {
        Self::Translation(error.to_string())
    }
}

/// Errors produced by serialized precompile STARK proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    /// The chiplet stack declares preprocessed columns, but no preprocessed
    /// bundle was produced. This should not happen for the full session AIR set.
    #[error("chiplet stack declares preprocessed columns, but no preprocessed bundle was built")]
    MissingPreprocessed,
    /// The preprocessed bundle did not match the declared AIR columns/config.
    #[error(transparent)]
    Preprocessed(#[from] miden_lifted_stark::PreprocessedValidationError),
    /// The lifted STARK prover rejected the instance.
    #[error(transparent)]
    Prover(#[from] miden_lifted_stark::ProverError),
    /// Failed to serialize the STARK proof data into the core proof envelope.
    #[error("failed to serialize STARK proof: {0}")]
    Serialization(#[from] wincode::error::WriteError),
}

pub(crate) mod deferred;

#[cfg(test)]
mod limit_tests {
    use alloc::vec;

    use miden_core::{deferred::TRUE_DIGEST, proof::HashFunction};

    use super::*;

    #[test]
    fn verify_deferred_enforces_fixed_stark_proof_size_ceiling() {
        let proof = StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Blake3_256);

        assert!(matches!(
            verify_deferred(&proof, TRUE_DIGEST),
            Err(VerifyError::ProofTooLarge {
                size,
                max: MAX_STARK_PROOF_BYTES,
            }) if size == MAX_STARK_PROOF_BYTES + 1
        ));
    }
}

#[cfg(test)]
mod tests;
