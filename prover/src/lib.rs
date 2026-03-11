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

// Trace conversion utilities
mod trace_adapter;

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
pub use trace_adapter::{aux_trace_to_row_major, execution_trace_to_row_major};

// PROVER
// ================================================================================================

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
///
/// This is an async function that works on all platforms including wasm32.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover
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

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, host).await?;

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
        let _span = tracing::info_span!("execution_trace_to_row_major").entered();
        execution_trace_to_row_major(&trace)
    };

    // Build public inputs and extract fixed/variable-length components
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

    // Get aux trace builders
    let aux_builder = trace.aux_trace_builders();

    // Generate STARK proof using lifted prover
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::create_blake3_256_config();
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Keccak => {
            let config = config::create_keccak_config();
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpo256 => {
            let config = config::create_rpo_config();
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Poseidon2 => {
            let config = config::create_poseidon2_config();
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpx256 => {
            let config = config::create_rpx_config();
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
    }?;

    let proof = ExecutionProof::new(proof_bytes, hash_fn, precompile_requests);

    Ok((stack_outputs, proof))
}

/// Synchronous wrapper for the async `prove()` function.
///
/// This method is only available on non-wasm32 targets. On wasm32, use the
/// async `prove()` method directly since wasm32 runs in the browser's event loop.
///
/// # Panics
/// Panics if called from within an existing Tokio runtime. Use the async `prove()`
/// method instead in async contexts.
#[cfg(not(target_arch = "wasm32"))]
#[instrument("prove_program_sync", skip_all)]
pub fn prove_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already inside a Tokio runtime - this is not supported
            // because we cannot safely create a nested runtime or move the
            // non-Send host reference to another thread
            panic!(
                "Cannot call prove_sync from within a Tokio runtime. \
                 Use the async prove() method instead."
            )
        },
        Err(_) => {
            // No runtime exists - create one and use it
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(prove(program, stack_inputs, advice_inputs, host, options))
        },
    }
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
    let air = ProcessorAir::default();
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
        &air,
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
