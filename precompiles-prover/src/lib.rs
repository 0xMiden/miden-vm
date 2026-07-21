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

use miden_core::deferred::{DeferredState, TRUE_DIGEST};
pub use miden_core::proof::{DeferredProof, HashFunction, StarkProof};
pub use session::{VerifyError, verify_deferred};

pub(crate) mod ec;
pub(crate) mod hash;
pub(crate) mod logup;
pub(crate) mod math;
pub(crate) mod primitives;
pub(crate) mod relations;
pub(crate) mod session;
pub(crate) mod stark_config;
pub(crate) mod transcript;
pub(crate) mod uint;
pub(crate) mod utils;

/// Proves the precompile claims accumulated in `state`.
///
/// Empty states produce [`DeferredProof::Empty`]. Non-empty states are translated into the private
/// precompile-prover session representation, finalized, and proved as [`DeferredProof::Stark`]
/// for `state.root()`.
pub fn prove_deferred_state(
    state: &DeferredState,
    hash_fn: HashFunction,
) -> Result<DeferredProof, ProveDeferredStateError> {
    if state.root() == TRUE_DIGEST {
        return Ok(DeferredProof::Empty);
    }

    let deferred = {
        let _span = tracing::info_span!("build_session").entered();
        deferred::session_from_deferred_state(state)?
    };
    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        deferred.session.finish(deferred.root)
    };
    Ok(traces.prove_deferred(hash_fn)?)
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
mod tests;
