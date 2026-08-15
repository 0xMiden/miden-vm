#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, vec, vec::Vec};

use ::serde::Serialize;
use miden_air::{MidenMultiAir, ProverStatement, Statement};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::stark::{
    ProverInstance, StarkConfig,
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProofData},
};
use serde_wincode::{SerdeCompat, wincode};
use tracing::instrument;

mod prover;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, MidenAir, PublicInputs, config};
pub use miden_core::proof::{ExecutionProof, HashFunction, PrecompileProof, StarkProof, VmProof};
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
    poseidon2_trace: RowMajorMatrix<Felt>,
    public_values: &[Felt],
    aux_inputs: &[Felt],
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction.
    let statement =
        Statement::new(MidenMultiAir::new(), public_values.to_vec(), aux_inputs.to_vec())
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    let prover_statement =
        ProverStatement::new(statement, vec![core_trace, chiplets_trace, poseidon2_trace])
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;

    let output: StarkOutput<Felt, QuadFelt, SC> =
        ProverInstance::new(config, &prover_statement, None)
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
