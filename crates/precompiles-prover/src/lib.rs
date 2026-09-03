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

pub use miden_core::proof::{HashFunction, StarkProof};
use miden_core::{deferred::DeferredState, utils::Matrix};
use miden_precompiles_air::{NUM_CHIPLETS, memory, stark_config::precompile_pcs_params};

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

/// Default maximum memory, in bytes, [`prove_deferred_state`] assumes when no budget is given
/// explicitly. Callers that own actual proving policy (e.g. `miden-prover`'s `Prover`) are
/// expected to set their own via [`prove_deferred_state_with_budget`].
pub const DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Proves the precompile claims accumulated in `state` against its exact deferred root.
pub fn prove_deferred_state(
    state: &DeferredState,
    hash_fn: HashFunction,
) -> Result<StarkProof, ProveDeferredStateError> {
    prove_deferred_state_with_budget(state, hash_fn, DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES)
}

/// Same as [`prove_deferred_state`], but with an explicit memory budget instead of the default.
///
/// Checks the modelled peak prover memory for the generated chiplet traces against
/// `max_prover_memory_bytes` before proving — the STARK pipeline's LDE, aux-trace expansion,
/// quotient polynomial, and Merkle trees dominate peak usage and are built inside proving.
pub fn prove_deferred_state_with_budget(
    state: &DeferredState,
    hash_fn: HashFunction,
    max_prover_memory_bytes: u64,
) -> Result<StarkProof, ProveDeferredStateError> {
    let deferred = {
        let _span = tracing::info_span!("build_session").entered();
        deferred::session_from_deferred_state(state)?
    };
    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        deferred.session.finish(deferred.root)
    };

    let heights: [usize; NUM_CHIPLETS] = traces.mains().map(|main| main.height());
    let params = precompile_pcs_params();
    let estimated_bytes = memory::prover_peak_bytes(&heights, &params).ok_or(
        ProveDeferredStateError::MemoryBudgetExceeded {
            estimated_bytes: u64::MAX,
            budget_bytes: max_prover_memory_bytes,
        },
    )?;
    if estimated_bytes > max_prover_memory_bytes {
        return Err(ProveDeferredStateError::MemoryBudgetExceeded {
            estimated_bytes,
            budget_bytes: max_prover_memory_bytes,
        });
    }

    Ok(traces.prove_stark(hash_fn)?)
}

/// Errors produced while proving deferred precompile claims from VM deferred state.
#[derive(Debug, thiserror::Error)]
pub enum ProveDeferredStateError {
    /// The VM deferred DAG could not be translated into the precompile prover's session model.
    #[error("failed to translate deferred state into a precompile proving session: {0}")]
    Translation(String),
    /// The modelled peak prover memory for the generated chiplet traces exceeds the configured
    /// budget.
    #[error(
        "estimated precompile prover memory of {estimated_bytes} bytes exceeds the budget of \
         {budget_bytes} bytes"
    )]
    MemoryBudgetExceeded { estimated_bytes: u64, budget_bytes: u64 },
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
