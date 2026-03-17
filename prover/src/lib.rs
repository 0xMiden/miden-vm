#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, vec::Vec};

use ::serde::Serialize;
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::{
    StarkConfig, air::VarLenPublicInputs, challenger::CanObserve, lmcs::Lmcs, proof::StarkOutput,
};
use miden_processor::{
    FastProcessor, Program,
    trace::{AuxTraceBuilders, build_trace},
};
use tracing::instrument;

mod proving_options;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, ProcessorAir, PublicInputs, config};
pub use miden_core::proof::{ExecutionProof, HashFunction};
pub use miden_processor::{
    ExecutionError, Host, InputError, StackInputs, StackOutputs, Word, advice::AdviceInputs,
    crypto, field, serde, utils,
};
pub use proving_options::ProvingOptions;

// PROVER
// ================================================================================================

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover.
/// - `options` defines parameters for STARK proof generation.
///
/// # Errors
/// Returns an error if program execution or STARK proof generation fails for any reason.
#[instrument("prove_program", skip_all)]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace using FastProcessor
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, *options.execution_options());

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, host)?;

    let trace = build_trace(execution_output, trace_generation_context, program.to_info())?;

    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps (padded from {})",
        miden_air::trace::TRACE_WIDTH,
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().trace_len()
    );

    let stack_outputs = *trace.stack_outputs();
    let precompile_requests = trace.precompile_requests().to_vec();
    let hash_fn = options.hash_fn();

    // Convert trace to row-major format
    let trace_matrix = {
        let _span = tracing::info_span!("to_row_major_matrix").entered();
        trace.to_row_major_matrix()
    };

    // Build public inputs and extract fixed/variable-length components
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

    // Get aux trace builders
    let aux_builder = trace.aux_trace_builders();

    // Generate STARK proof using lifted prover
    let params = config::pcs_params();
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
    }?;

    let proof = ExecutionProof::new(proof_bytes, hash_fn, precompile_requests);

    Ok((stack_outputs, proof))
}

/// Async compatibility wrapper for [`prove`].
#[instrument("prove_program_async", skip_all)]
pub async fn prove_async(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    prove(program, stack_inputs, advice_inputs, host, options)
}

// STARK PROOF GENERATION
// ================================================================================================

/// Generates a STARK proof for the given trace and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// prover. Returns the serialized proof bytes.
pub fn prove_stark<SC>(
    config: &SC,
    trace: &RowMajorMatrix<Felt>,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    aux_builder: &AuxTraceBuilders,
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let log_trace_height = trace.height().ilog2() as u8;

    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    // TODO: observe log_trace_height in the transcript for Fiat-Shamir binding.
    // TODO: observe var_len_public_inputs in the transcript for Fiat-Shamir binding.
    //   This also requires updating the recursive verifier to absorb both fixed and
    //   variable-length public inputs.
    // TODO: observe ACE commitment once ACE verification is integrated.
    // See https://github.com/0xMiden/miden-vm/issues/2822
    let output: StarkOutput<Felt, QuadFelt, SC> = miden_crypto::stark::prover::prove_single(
        config,
        &ProcessorAir,
        trace,
        public_values,
        var_len_public_inputs,
        aux_builder,
        challenger,
    )
    .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    // Proof serialization via bincode; see https://github.com/0xMiden/miden-vm/issues/2550
    // We serialize `(log_trace_height, proof)` as a tuple; this is a temporary approach until
    // the lifted STARK integrates trace height on its side.
    let proof_bytes = bincode::serialize(&(log_trace_height, &output.proof))
        .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}
