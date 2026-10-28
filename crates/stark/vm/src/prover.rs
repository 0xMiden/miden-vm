use alloc::{string::ToString, vec, vec::Vec};

use ::serde::Serialize;
use miden_air::vm::{MidenMultiAir, config};
use miden_air_definitions::vm::VmTrace;
use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, VmProof},
    utils::RowMajorMatrix,
};
use miden_stark::{
    Preprocessed, ProverInstance, StarkConfig,
    air::{ProverStatement, Statement},
    config::{blake3_256_config, keccak_config, observe_protocol_params},
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProofData},
};
use serde_wincode::{SerdeCompat, wincode};
use tracing::instrument;

use crate::setup::config::eidos_config;
#[cfg(feature = "std")]
use crate::setup::preprocessed::cached_preprocessed_setup;

/// Failure while producing a VM STARK proof.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProvingError(pub alloc::string::String);

/// Proves a completed VM trace using the selected commitment hash.
///
/// `hash_lde_blocks` hashes completed blocks during the final trace LDE when supported by the
/// commitment scheme. It changes scheduling while preserving commitments and proof bytes.
#[tracing::instrument(name = "miden_vm", skip_all)]
pub fn prove(
    trace: VmTrace,
    hash_fn: HashFunction,
    hash_lde_blocks: bool,
) -> Result<VmProof, ProvingError> {
    let trace_len_summary = trace.trace_len_summary();
    let params = config::pcs_params();
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution traces: core={}, chiplets={}, eidos_compression={}, and8={}, padded={}, \
             estimated_prover_memory_bytes={:?}",
        trace_len_summary.core_rows(),
        trace_len_summary.chiplets_rows(),
        trace_len_summary.eidos_compression_rows(),
        trace_len_summary.byte_pair_lookup_rows(),
        trace_len_summary.padded_trace_len(),
        crate::memory::prover_peak_bytes(trace_len_summary.padded_heights(), &params)
    );

    let precompile_root = trace.precompile_root();
    let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();
    let (core_matrix, chiplets_matrix, eidos_compression_matrix, and8_matrix) =
        trace.into_air_matrices();

    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let mut config = blake3_256_config(params, config::RELATION_DIGEST);
            config.hash_lde_blocks = hash_lde_blocks;
            prove_stark(
                &config,
                core_matrix,
                chiplets_matrix,
                eidos_compression_matrix,
                and8_matrix,
                &public_values,
                &aux_inputs,
            )
        },
        HashFunction::Keccak => {
            let mut config = keccak_config(params, config::RELATION_DIGEST);
            config.hash_lde_blocks = hash_lde_blocks;
            prove_stark(
                &config,
                core_matrix,
                chiplets_matrix,
                eidos_compression_matrix,
                and8_matrix,
                &public_values,
                &aux_inputs,
            )
        },
        HashFunction::Eidos => {
            let mut config = eidos_config(params, config::RELATION_DIGEST);
            config.hash_lde_blocks = hash_lde_blocks;
            prove_stark(
                &config,
                core_matrix,
                chiplets_matrix,
                eidos_compression_matrix,
                and8_matrix,
                &public_values,
                &aux_inputs,
            )
        },
    }?;

    let proof = miden_core::proof::StarkProof::new(proof_bytes, hash_fn);
    Ok(VmProof { proof, precompile_root })
}

// STARK PROOF GENERATION
// ================================================================================================

/// Generates a multi-AIR STARK proof for the Miden trace set and public values.
///
/// Pre-seeds the challenger with the protocol parameters, the AIR public values, and the
/// statement `aux_inputs` (program hash, final deferred root, and the concatenated kernel-procedure
/// digests). Then delegates to the lifted multi-AIR prover.
#[instrument("prove_stark", skip_all)]
pub(crate) fn prove_stark<SC>(
    config: &SC,
    core_trace: RowMajorMatrix<Felt>,
    chiplets_trace: RowMajorMatrix<Felt>,
    eidos_compression_trace: RowMajorMatrix<Felt>,
    and8_trace: RowMajorMatrix<Felt>,
    public_values: &[Felt],
    aux_inputs: &[Felt],
) -> Result<Vec<u8>, ProvingError>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
    Preprocessed<Felt, SC::Lmcs>: Send + Sync,
{
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction.
    let statement = Statement::new(
        MidenMultiAir::new(),
        vec![(0, public_values.to_vec())],
        aux_inputs.to_vec(),
    )
    .map_err(|e| ProvingError(e.to_string()))?;
    let prover_statement = ProverStatement::new(
        statement,
        vec![core_trace, chiplets_trace, eidos_compression_trace, and8_trace],
    )
    .map_err(|e| ProvingError(e.to_string()))?;

    #[cfg(feature = "std")]
    let preprocessed_arc = cached_preprocessed_setup(prover_statement.statement(), config);
    #[cfg(feature = "std")]
    let preprocessed = preprocessed_arc.as_deref();
    #[cfg(not(feature = "std"))]
    let preprocessed_owned = Preprocessed::build(prover_statement.statement(), config);
    #[cfg(not(feature = "std"))]
    let preprocessed = preprocessed_owned.as_ref();

    let (output, _statement): (StarkOutput<Felt, QuadFelt, SC>, _) =
        ProverInstance::new(config, prover_statement, preprocessed)
            .map_err(|e| ProvingError(e.to_string()))?
            .prove(challenger)
            .map_err(|e| ProvingError(e.to_string()))?;

    let proof_encoding_config = wincode::config::Configuration::default();
    let proof_bytes =
        <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<_>>::serialize(
            &output.proof,
            proof_encoding_config,
        )
        .map_err(|e| ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}
