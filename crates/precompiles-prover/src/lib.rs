#![no_std]
#![allow(
    dead_code,
    unused_imports,
    reason = "the imported prover stack is intentionally retained behind a narrow crate API"
)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

use alloc::vec::Vec;

pub use deferred::session::{SessionInputError, WitnessLocation};
use miden_core::deferred::{PrecompileLimits, PrecompileWitness};
pub use miden_core::proof::{HashFunction, PrecompileProof, StarkProof};
pub use miden_precompiles::default_precompile_limits;

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

/// Default maximum memory, in bytes, [`prove_precompiles`] assumes when no budget is given
/// explicitly. Callers that own actual proving policy (e.g. `miden-prover`'s `Prover`) are
/// expected to set their own via [`prove_precompiles_with_budget`].
pub const DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Proves an owned batch of singleton execution obligations in one STARK.
///
/// The returned roots preserve input order and repetitions. Empty batches are rejected. The
/// importer prepares and admits each portable witness independently before sharing computations.
pub fn prove_precompiles(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_limits_and_budget(
        witnesses,
        hash_fn,
        &default_precompile_limits(),
        DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES,
    )
}

/// Same as [`prove_precompiles`], but with an explicit memory budget instead of the default.
///
/// Checks the modelled peak prover memory against `max_prover_memory_bytes` before allocating
/// chiplet traces or entering the STARK pipeline. The budget applies to this single proof using
/// `hash_fn`; concurrent proofs require separate budgeting. Witness import precedes the check.
pub fn prove_precompiles_with_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_limits_and_budget(
        witnesses,
        hash_fn,
        &default_precompile_limits(),
        max_prover_memory_bytes,
    )
}

/// Proves a batch with explicit per-witness logical limits and a batch prover-memory budget.
pub fn prove_precompiles_with_limits_and_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    limits: &PrecompileLimits,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove(witnesses, hash_fn, limits, None, max_prover_memory_bytes)
}

/// Proves one witness after binding its prepared root to the execution-established root.
pub fn prove_precompile_for_root_with_limits_and_budget(
    witness: PrecompileWitness,
    expected_root: miden_core::Word,
    hash_fn: HashFunction,
    limits: &PrecompileLimits,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove(
        alloc::vec![witness],
        hash_fn,
        limits,
        Some(core::slice::from_ref(&expected_root)),
        max_prover_memory_bytes,
    )
}

fn check_memory_budget(
    estimated_bytes: Option<u64>,
    budget_bytes: u64,
) -> Result<(), PrecompileProvingError> {
    let estimated_bytes = estimated_bytes.ok_or(PrecompileProvingError::MemoryEstimateOverflow)?;
    if estimated_bytes > budget_bytes {
        return Err(PrecompileProvingError::MemoryBudgetExceeded { estimated_bytes, budget_bytes });
    }
    Ok(())
}

/// Errors produced while importing and proving portable precompile claims.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileProvingError {
    #[error(transparent)]
    Input(#[from] SessionInputError),
    /// The prover memory estimate exceeded the host height range or the byte model's `u64` range.
    #[error("precompile prover memory estimate overflowed")]
    MemoryEstimateOverflow,
    /// The modelled peak prover memory for the generated chiplet traces exceeds the configured
    /// budget.
    #[error(
        "estimated precompile prover memory of {estimated_bytes} bytes exceeds the budget of \
         {budget_bytes} bytes"
    )]
    MemoryBudgetExceeded { estimated_bytes: u64, budget_bytes: u64 },
    #[error(transparent)]
    Prove(#[from] ProveError),
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
