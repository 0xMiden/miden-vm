#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_air::ProcessorAir;
use miden_processor::{
    Program,
    fast::FastProcessor,
    math::Felt,
    parallel::build_trace,
};
use tracing::instrument;

// Trace conversion utilities
mod trace_adapter;

// EXPORTS
// ================================================================================================

pub use miden_air::{DeserializationError, ExecutionProof, HashFunction, ProvingOptions, config};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, StackInputs, StackOutputs,
    SyncHost, Word, crypto, math, utils,
};
pub use miden_prover_p3::{Commitments, OpenedValues, Proof};
pub use trace_adapter::{aux_trace_to_row_major, execution_trace_to_row_major};

// PROVER
// ================================================================================================

/// Default fragment size for trace generation.
const DEFAULT_FRAGMENT_SIZE: usize = 1 << 16;

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover
/// - `options` defines parameters for STARK proof generation.
///
/// # Errors
/// Returns an error if program execution or STARK proof generation fails for any reason.
#[instrument("prove_program", skip_all)]
pub fn prove(
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

    let processor = if options.execution_options().enable_debugging() {
        FastProcessor::new_debug(&stack_inputs_reversed, advice_inputs)
    } else {
        FastProcessor::new_with_advice_inputs(&stack_inputs_reversed, advice_inputs)
    };

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace_sync(program, host, DEFAULT_FRAGMENT_SIZE)?;

    let trace = build_trace(
        execution_output,
        trace_generation_context,
        program.hash(),
        program.kernel().clone(),
    );

    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps (padded from {})",
        miden_air::TRACE_WIDTH,
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().main_trace_len()
    );

    let stack_outputs = *trace.stack_outputs();
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
        HashFunction::Blake3_192 => {
            // TODO: Proper 192-bit support requires Plonky3 to implement
            // CryptographicHasher<u8, [u8; 24]> for Blake3.
            panic!("Blake3_192 is not yet supported")
        },
        HashFunction::Blake3_256 => {
            let config = miden_air::config::create_blake3_256_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
        },
        HashFunction::Keccak => {
            let config = miden_air::config::create_keccak_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
        },
        HashFunction::Rpo256 => {
            let config = miden_air::config::create_rpo_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
        },
        HashFunction::Poseidon2 => {
            let config = miden_air::config::create_poseidon2_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
        },
        HashFunction::Rpx256 => {
            let config = miden_air::config::create_rpx_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
        },
    };

    let proof = miden_air::ExecutionProof::new(proof_bytes, hash_fn, precompile_requests);

    Ok((stack_outputs, proof))
}
