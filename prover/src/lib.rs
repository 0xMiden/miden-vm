#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use alloc::boxed::Box;
use alloc::{string::ToString, vec, vec::Vec};
#[cfg(feature = "std")]
use core::any::{Any, TypeId};

use ::serde::Serialize;
use miden_air::{MidenMultiAir, ProverStatement, Statement};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::stark::{
    Preprocessed, ProverInstance, StarkConfig,
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProofData},
};
use serde_wincode::{SerdeCompat, wincode};
use tracing::instrument;

#[cfg(feature = "std")]
type PreprocessedSetup<SC> = Preprocessed<Felt, <SC as StarkConfig<Felt, QuadFelt>>::Lmcs>;

#[cfg(feature = "std")]
type PreprocessedCache = std::collections::HashMap<(TypeId, u8), Box<dyn Any + Send + Sync>>;

#[cfg(feature = "std")]
static PREPROCESSED_SETUPS: std::sync::OnceLock<std::sync::Mutex<PreprocessedCache>> =
    std::sync::OnceLock::new();

mod prover;

#[cfg(all(test, feature = "std"))]
mod overflow_pointer_soundness_repro;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, MidenAir, PublicInputs, config};
pub use miden_core::proof::{
    ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof,
};
pub use miden_processor::{
    ExecutionClaim, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FutureMaybeSend, Host, InputError, PrecompileWitness, ProgramInfo, StackInputs, StackOutputs,
    SyncHost, VmWitness, Word, advice::AdviceInputs, crypto, field, serde, utils,
};
pub use prover::{Prover, ProverError, prove_sync};

// STARK PROOF GENERATION
// ================================================================================================

/// Generates a multi-AIR STARK proof for the Miden trace set and public values.
///
/// Pre-seeds the challenger with the protocol parameters, the AIR public values, and the
/// statement `aux_inputs` (program hash, final deferred root, and the concatenated kernel-procedure
/// digests). Then delegates to the lifted multi-AIR prover.
#[instrument("prove_stark", skip_all)]
fn prove_stark<SC>(
    config: &SC,
    core_trace: RowMajorMatrix<Felt>,
    chiplets_trace: RowMajorMatrix<Felt>,
    eidos_compression_trace: RowMajorMatrix<Felt>,
    and8_trace: RowMajorMatrix<Felt>,
    public_values: &[Felt],
    aux_inputs: &[Felt],
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
    Preprocessed<Felt, SC::Lmcs>: Send + Sync,
{
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction.
    let statement =
        Statement::new(MidenMultiAir::new(), public_values.to_vec(), aux_inputs.to_vec())
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    let prover_statement = ProverStatement::new(
        statement,
        vec![core_trace, chiplets_trace, eidos_compression_trace, and8_trace],
    )
    .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;

    #[cfg(feature = "std")]
    let preprocessed_arc = cached_preprocessed_setup(prover_statement.statement(), config);
    #[cfg(feature = "std")]
    let preprocessed = preprocessed_arc.as_deref();
    #[cfg(not(feature = "std"))]
    let preprocessed_owned = Preprocessed::build(prover_statement.statement(), config);
    #[cfg(not(feature = "std"))]
    let preprocessed = preprocessed_owned.as_ref();

    let output: StarkOutput<Felt, QuadFelt, SC> =
        ProverInstance::new(config, &prover_statement, preprocessed)
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?
            .prove(challenger)
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;

    let proof_encoding_config = wincode::config::Configuration::default();
    let proof_bytes =
        <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<_>>::serialize(
            &output.proof,
            proof_encoding_config,
        )
        .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}

/// Returns the (possibly cached) preprocessed setup for `config`.
///
/// The verifier only needs the fixed setup commitment. The prover needs the
/// full setup tree so it can open preprocessed rows during PCS queries. The
/// setup depends only on the concrete config type and LDE blowup, so it is
/// cached per `(TypeId, log_blowup)` across proves.
#[cfg(feature = "std")]
fn cached_preprocessed_setup<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> Option<std::sync::Arc<PreprocessedSetup<SC>>>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    PreprocessedSetup<SC>: Send + Sync + 'static,
{
    let key = (TypeId::of::<SC>(), config.pcs().log_blowup());
    let mut cache = PREPROCESSED_SETUPS
        .get_or_init(Default::default)
        .lock()
        .expect("preprocessed setup cache poisoned");

    if let Some(value) = cache.get(&key) {
        return value
            .downcast_ref::<Option<std::sync::Arc<PreprocessedSetup<SC>>>>()
            .expect("preprocessed setup cache type mismatch")
            .clone();
    }

    let value = Preprocessed::build(statement, config).map(std::sync::Arc::new);
    cache.insert(key, Box::new(value.clone()));
    value
}
