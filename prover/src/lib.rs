#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, vec::Vec};

use miden_processor::{FastProcessor, Program, trace::build_trace};
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
    let pub_inputs = PublicInputs::new(
        trace.program_info().clone(),
        trace.init_stack_state(),
        *trace.stack_outputs(),
        trace.final_precompile_transcript().state(),
    );
    let (public_values, kernel_digests) = pub_inputs.to_air_inputs();
    let var_len_refs: Vec<&[_]> = kernel_digests.iter().map(|w| w.as_ref()).collect();
    let var_len_public_inputs: &[&[_]] = &var_len_refs;

    // Create AIR
    let air = ProcessorAir::new(kernel_digests.len());

    // Get aux trace builders
    let aux_builder = trace.aux_trace_builders();

    // Compute log_trace_height
    let log_trace_height = trace.trace_len_summary().padded_trace_len().ilog2();

    // Generate STARK proof using lifted prover
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::create_blake3_256_config();
            config::prove(
                &config,
                &air,
                &trace_matrix,
                &public_values,
                var_len_public_inputs,
                &aux_builder,
            )
        },
        HashFunction::Keccak => {
            let config = config::create_keccak_config();
            config::prove(
                &config,
                &air,
                &trace_matrix,
                &public_values,
                var_len_public_inputs,
                &aux_builder,
            )
        },
        HashFunction::Rpo256 => {
            let config = config::create_rpo_config();
            config::prove(
                &config,
                &air,
                &trace_matrix,
                &public_values,
                var_len_public_inputs,
                &aux_builder,
            )
        },
        HashFunction::Poseidon2 => {
            let config = config::create_poseidon2_config();
            config::prove(
                &config,
                &air,
                &trace_matrix,
                &public_values,
                var_len_public_inputs,
                &aux_builder,
            )
        },
        HashFunction::Rpx256 => {
            let config = config::create_rpx_config();
            config::prove(
                &config,
                &air,
                &trace_matrix,
                &public_values,
                var_len_public_inputs,
                &aux_builder,
            )
        },
    }
    .map_err(|e| ExecutionError::ProvingError(Box::new(e)))?;

    let proof = ExecutionProof::new(proof_bytes, hash_fn, log_trace_height, precompile_requests);

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
