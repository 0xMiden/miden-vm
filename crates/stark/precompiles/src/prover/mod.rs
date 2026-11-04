//! Portable-witness lowering, trace construction, and proving for the precompile relation.

use alloc::vec::Vec;

#[cfg(feature = "testing")]
pub use deferred::session::testing;
pub use deferred::session::{SessionInputError, WitnessLocation};
use miden_core::deferred::{PrecompileLimits, PrecompileWitness};
pub use miden_core::proof::{HashFunction, PrecompileProof, StarkProof};
use miden_precompiles::default_verification_precompile_limits;

pub(crate) mod ec;
pub(crate) mod hash;
#[cfg(test)]
pub(crate) mod logup;
pub(crate) mod math;
pub(crate) mod primitives;
pub(crate) mod relations;
pub(crate) mod session;
#[cfg(test)]
pub(crate) mod stark_config;
pub(crate) mod transcript;
pub(crate) mod uint;
pub(crate) mod utils;

/// Default maximum modelled peak memory, in bytes, used by [`prove_precompiles`] when no budget is
/// given explicitly. Callers that own actual proving policy (e.g. `miden-prover`'s `Prover`) are
/// expected to set their own via [`prove_precompiles_with_budget`].
pub const DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Proves an owned batch of singleton execution obligations in one STARK.
///
/// The returned roots preserve input order and repetitions. Empty batches and batches exceeding
/// [`miden_core::deferred::MAX_PRECOMPILE_ROOTS`] are rejected before preparation. Every portable
/// witness is consumed and prepared under verification limits before a private Session shares
/// computations. Session import does not reapply workload admission.
pub fn prove_precompiles(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_limits_and_budget(
        witnesses,
        hash_fn,
        &default_verification_precompile_limits(),
        DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES,
    )
}

/// Same as [`prove_precompiles`], but with an explicit memory budget instead of the default.
///
/// Checks conservative capacity estimates before preparing each witness, constructing the Session,
/// and recording each new node or aggregate fold. Preparation counts repeated witnesses; import
/// shares cached nodes. The final check uses the actual padded chiplet heights before allocating
/// traces or entering the STARK pipeline. These estimates are not an allocator quota or a bound on
/// process RSS, caller-owned inputs, or concurrent proofs. A capacity error can be addressed with
/// a smaller batch or a larger memory budget. Per-witness verification limits remain independent.
pub fn prove_precompiles_with_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    prove_precompiles_with_limits_and_budget(
        witnesses,
        hash_fn,
        &default_verification_precompile_limits(),
        max_prover_memory_bytes,
    )
}

/// Proves a batch with explicit per-witness verification limits and a batch prover-memory budget.
pub fn prove_precompiles_with_limits_and_budget(
    witnesses: Vec<PrecompileWitness>,
    hash_fn: HashFunction,
    verification_limits: &PrecompileLimits,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove(witnesses, hash_fn, verification_limits, None, max_prover_memory_bytes)
}

/// Proves one witness after binding its prepared root to the execution-established root.
pub fn prove_precompile_for_root_with_limits_and_budget(
    witness: PrecompileWitness,
    expected_root: miden_core::Word,
    hash_fn: HashFunction,
    verification_limits: &PrecompileLimits,
    max_prover_memory_bytes: u64,
) -> Result<PrecompileProof, PrecompileProvingError> {
    deferred::session::prove(
        alloc::vec![witness],
        hash_fn,
        verification_limits,
        Some(core::slice::from_ref(&expected_root)),
        max_prover_memory_bytes,
    )
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
    /// A preparation, Session recording, or trace-proving memory estimate exceeds the budget.
    ///
    /// A preparation or recording rejection reports the running reservation at the rejected step,
    /// a lower bound on the batch requirement. A trace-proving rejection reports the full modelled
    /// peak for the recorded Session.
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
    Preprocessed(#[from] miden_stark::PreprocessedValidationError),
    /// The lifted STARK prover rejected the instance.
    #[error(transparent)]
    Prover(#[from] miden_stark::ProverError),
    /// Failed to serialize the STARK proof data into the core proof envelope.
    #[error("failed to serialize STARK proof: {0}")]
    Serialization(#[from] wincode::error::WriteError),
}

pub(crate) mod deferred;

#[cfg(test)]
mod tests;
