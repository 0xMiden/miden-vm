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
use miden_core::deferred::{Digest, PrecompileLimits, PrecompileWitness};
pub use miden_core::proof::{HashFunction, PrecompileProof, StarkProof};
pub use miden_precompiles::default_precompile_limits;
use miden_precompiles_air::{memory, stark_config::precompile_pcs_params};
use session::{Session, Truthy};

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
/// The returned roots preserve input order and repetitions. Empty batches and batches exceeding
/// [`miden_core::deferred::MAX_PRECOMPILE_ROOTS`] are rejected before preparation. Every portable
/// witness is consumed and admitted independently before a private Session shares computations.
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
/// `hash_fn`; concurrent proofs require separate budgeting. Witness import precedes the check,
/// so this is not an allocation budget for preparation or Session construction. A capacity error
/// can be addressed with a smaller batch or a larger memory budget.
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
    prove(witnesses, hash_fn, limits, None, max_prover_memory_bytes)
}

/// Proves one witness after binding its prepared root to the execution-established root.
pub fn prove_precompile_for_root_with_limits_and_budget(
    witness: PrecompileWitness,
    expected_root: miden_core::Word,
    hash_fn: HashFunction,
    limits: &PrecompileLimits,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove(
        alloc::vec![witness],
        hash_fn,
        limits,
        Some(core::slice::from_ref(&expected_root)),
        max_prover_memory_bytes,
    )
}

pub(crate) struct WitnessSession {
    session: Session,
    root: Truthy,
    roots: Vec<Digest>,
}

impl WitnessSession {
    #[cfg(test)]
    pub(crate) fn finish(self) -> session::SessionTraces {
        self.session.finish(self.root)
    }
}

fn prove(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    limits: &PrecompileLimits,
    expected_roots: Option<&[Digest]>,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    let imported = {
        let _span = tracing::info_span!("build_session").entered();
        deferred::session::import_witnesses_with_roots(witnesses, limits, expected_roots)?
    };
    let params = precompile_pcs_params();
    let estimated_bytes = imported
        .session
        .trace_heights()
        .and_then(|heights| memory::prover_peak_bytes(&heights, &params, hash_fn));
    check_memory_budget(estimated_bytes, max_prover_memory_bytes)?;

    let traces = {
        let _span = tracing::info_span!("build_trace").entered();
        imported.session.finish(imported.root)
    };
    Ok(PrecompileProof {
        proof: traces.prove_stark(hash_fn)?,
        roots: imported.roots,
    })
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
    /// The requested batch exceeds the shared proof-root capacity, before witness preparation.
    #[error("precompile batch contains {witnesses} witnesses, maximum is {max}")]
    BatchTooLarge { witnesses: usize, max: usize },
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
