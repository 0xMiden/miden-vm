#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, vec::Vec};

use ::serde::Serialize;
use miden_core::{
    Felt, WORD_SIZE,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::{
    StarkConfig, air::VarLenPublicInputs, challenger::CanObserve, lmcs::Lmcs, proof::StarkOutput,
};
use miden_processor::{
    FastProcessor, Program,
    trace::{AuxTraceBuilders, ExecutionTrace, build_trace},
};
use tracing::instrument;

mod proving_options;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, ProcessorAir, PublicInputs, config};
pub use miden_core::proof::{ExecutionProof, HashFunction};
pub use miden_processor::{
    ExecutionError, ExecutionOutput, FutureMaybeSend, Host, InputError, ProgramInfo, StackInputs,
    StackOutputs, SyncHost, TraceBuildInputs, TraceGenerationContext, Word, advice::AdviceInputs,
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
pub async fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace using FastProcessor
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, *options.execution_options());

    let trace_inputs = processor.execute_trace_inputs(program, host).await?;
    prove_from_trace_sync(trace_inputs, options)
}

/// Synchronous wrapper for the async `prove()` function.
#[instrument("prove_program_sync", skip_all)]
pub fn prove_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, *options.execution_options());

    let trace_inputs = processor.execute_trace_inputs_sync(program, host)?;
    prove_from_trace_sync(trace_inputs, options)
}

/// Builds an execution trace from pre-executed trace inputs and proves it synchronously.
///
/// This is useful when program execution has already happened elsewhere and only trace building
/// plus proof generation remain.
#[instrument("prove_trace_sync", skip_all)]
pub fn prove_from_trace_sync(
    trace_inputs: TraceBuildInputs,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let trace = build_trace(trace_inputs)?;
    prove_execution_trace(trace, options)
}

fn prove_execution_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
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

    let trace_matrix = {
        let _span = tracing::info_span!("to_row_major_matrix").entered();
        trace.to_row_major_matrix()
    };

    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];
    let aux_builder = trace.aux_trace_builders();

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
    config::observe_protocol_params(&mut challenger, log_trace_height as u64);
    challenger.observe_slice(public_values);
    config::observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);
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
