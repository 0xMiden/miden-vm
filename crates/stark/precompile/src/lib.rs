#![no_std]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;
pub mod setup;
pub mod verifier;
pub use verifier::{VerifyError, verify_deferred};
#[cfg(test)]
mod ace;
#[cfg(test)]
mod ace_constants;
#[cfg(feature = "recursive")]
pub mod recursive;
#[cfg(feature = "prover")]
use alloc::vec::Vec;

#[cfg(feature = "trace")]
pub use deferred::session::{SessionInputError, WitnessLocation};
#[cfg(feature = "prover")]
use miden_core::deferred::PrecompileWitness;
pub use miden_core::deferred::PvmAirVariant;
pub use miden_core::proof::{HashFunction, PrecompileProof, StarkProof};

#[cfg(feature = "trace")]
pub(crate) mod ec;
#[cfg(feature = "trace")]
pub(crate) mod hash;
#[cfg(all(test, feature = "prover"))]
pub(crate) mod logup;
#[cfg(feature = "trace")]
pub(crate) mod math;
#[cfg(feature = "trace")]
pub(crate) mod primitives;
#[cfg(feature = "trace")]
pub(crate) mod relations;
#[cfg(feature = "trace")]
pub mod session;
#[cfg(all(test, feature = "prover"))]
pub(crate) mod stark_config;
#[cfg(feature = "trace")]
pub(crate) mod transcript;
#[cfg(feature = "trace")]
pub(crate) mod uint;
#[cfg(feature = "trace")]
pub(crate) mod utils;

/// Default maximum memory, in bytes, [`prove_precompiles`] assumes when no budget is given
/// explicitly. Callers that own actual proving policy (e.g. `miden-vm::proofs::Prover`) are
/// expected to set their own via [`prove_precompiles_with_budget`].
pub const DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Proves an owned batch of singleton execution obligations in one STARK.
///
/// The returned roots preserve input order and repetitions. Empty batches are rejected. The
/// importer validates portable semantics and enforces batch-wide input and lowering limits.
#[cfg(feature = "prover")]
pub fn prove_precompiles(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_budget(witnesses, hash_fn, DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES)
}

/// Same as [`prove_precompiles`], but with an explicit memory budget instead of the default.
///
/// Checks the modelled peak prover memory against `max_prover_memory_bytes` before allocating
/// chiplet traces or entering the STARK pipeline. The budget applies to this single proof using
/// `hash_fn`; concurrent proofs require separate budgeting. Witness import precedes the check.
#[cfg(feature = "prover")]
pub fn prove_precompiles_with_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove(witnesses, hash_fn, max_prover_memory_bytes)
}

/// Proves a batch using an explicit optional hash AIR selection and the default memory budget.
///
/// Witnesses that use a hash absent from `variant` are rejected before lowering. Unlike
/// [`prove_precompiles`], this uses the exact requested selection, including unused hash AIRs.
#[cfg(feature = "prover")]
pub fn prove_precompiles_with_variant(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    variant: PvmAirVariant,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_variant_and_budget(
        witnesses,
        hash_fn,
        variant,
        DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES,
    )
}

/// Same as [`prove_precompiles_with_variant`], with an explicit memory budget.
///
/// Only the selected AIRs contribute to the memory estimate and generated traces.
#[cfg(feature = "prover")]
pub fn prove_precompiles_with_variant_and_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    variant: PvmAirVariant,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove_with_variant(witnesses, hash_fn, variant, max_prover_memory_bytes)
}

#[cfg(feature = "prover")]
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
#[cfg(feature = "prover")]
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
#[cfg(feature = "prover")]
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    /// The chiplet stack declares preprocessed columns, but no preprocessed
    /// bundle was produced. This should not happen for the full session AIR set.
    #[error("chiplet stack declares preprocessed columns, but no preprocessed bundle was built")]
    MissingPreprocessed,
    /// The preprocessed bundle did not match the declared AIR columns/config.
    #[error(transparent)]
    Preprocessed(#[from] miden_stark::PreprocessedValidationError),
    /// The lifted STARK prover rejected the instance.
    #[error(transparent)]
    Prover(#[from] miden_stark::ProverError),
    /// Failed to serialize the STARK proof data into the core proof envelope.
    #[error("failed to serialize STARK proof: {0}")]
    Serialization(#[from] wincode::error::WriteError),
}

#[cfg(feature = "trace")]
pub(crate) mod deferred;

#[cfg(all(test, feature = "prover"))]
mod tests;

#[cfg(feature = "trace")]
pub mod trace {
    pub use crate::{
        deferred::session::{SessionInputError, WitnessLocation, WitnessSession},
        session::{Session, SessionTraces},
    };
    pub fn import_witnesses(
        witnesses: alloc::vec::Vec<miden_core::deferred::PrecompileWitness>,
    ) -> Result<WitnessSession, SessionInputError> {
        crate::deferred::session::import_witnesses(
            witnesses,
            crate::deferred::session::ImportLimits::default(),
        )
    }
}
#[cfg(feature = "prover")]
pub mod prover {
    pub use crate::{
        DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES, PrecompileProvingError, ProveError,
        prove_precompiles, prove_precompiles_with_budget, prove_precompiles_with_variant,
        prove_precompiles_with_variant_and_budget,
    };
}
