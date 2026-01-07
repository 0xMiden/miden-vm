#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::string::ToString;

use miden_processor::{Program, fast::FastProcessor, math::Felt, parallel::build_trace};
use tracing::instrument;

// Trace conversion utilities
mod trace_adapter;

// EXPORTS
// ================================================================================================

pub use miden_air::{
    DEFAULT_CORE_TRACE_FRAGMENT_SIZE, DeserializationError, ExecutionProof, HashFunction,
    ProcessorAir, ProvingOptions, config,
};
pub use miden_crypto::{
    stark,
    stark::{Commitments, OpenedValues, Proof},
};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, StackInputs, StackOutputs,
    SyncHost, Word, crypto, math, utils,
};
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
    host: &mut impl AsyncHost,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace using FastProcessor

    // Reverse stack inputs since FastProcessor expects them in reverse order
    // (first element = bottom of stack, last element = top)
    let stack_inputs_reversed: alloc::vec::Vec<Felt> = stack_inputs.iter().copied().rev().collect();

    let processor = FastProcessor::new_with_options(
        &stack_inputs_reversed,
        advice_inputs,
        *options.execution_options(),
    );

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, host).await?;

    let trace = build_trace(
        execution_output,
        trace_generation_context,
        program.hash(),
        program.kernel().clone(),
    );

    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps (padded from {})",
        miden_air::trace::TRACE_WIDTH,
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().main_trace_len()
    );

    let stack_outputs = trace.stack_outputs().clone();
    let precompile_requests = trace.precompile_requests().to_vec();
    let hash_fn = options.hash_fn();

    // Convert trace to row-major format
    let trace_matrix = {
        let _span = tracing::info_span!("execution_trace_to_row_major").entered();
        execution_trace_to_row_major(&trace)
    };

    // Build public values
    let public_values = trace.to_public_values();

    // Create AIR with aux trace builders
    let air = ProcessorAir::with_aux_builder(trace.aux_trace_builders().clone());

    // Generate STARK proof using unified miden-prover
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = miden_air::config::create_blake3_256_config();
            let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
            serialize_proof(&proof)?
        },
        HashFunction::Keccak => {
            let config = miden_air::config::create_keccak_config();
            let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
            serialize_proof(&proof)?
        },
        HashFunction::Rpo256 => {
            let config = miden_air::config::create_rpo_config();
            let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
            serialize_proof(&proof)?
        },
        HashFunction::Poseidon2 => {
            let config = miden_air::config::create_poseidon2_config();
            let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
            serialize_proof(&proof)?
        },
        HashFunction::Rpx256 => {
            let config = miden_air::config::create_rpx_config();
            let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
            serialize_proof(&proof)?
        },
    };

    let proof = miden_air::ExecutionProof::new(proof_bytes, hash_fn, precompile_requests);

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
    host: &mut impl AsyncHost,
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

// HELPER FUNCTIONS
// ================================================================================================

/// Serializes a proof to bytes, converting serialization errors to ExecutionError.
fn serialize_proof<T: serde::Serialize>(proof: &T) -> Result<alloc::vec::Vec<u8>, ExecutionError> {
    bincode::serialize(proof).map_err(|e| ExecutionError::ProofSerializationError(e.to_string()))
}
