#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_air::ProcessorAir;
use miden_processor::Program;
use tracing::instrument;

// Trace and public input conversion utilities
mod public_inputs;
mod trace_adapter;

// EXPORTS
// ================================================================================================

pub use miden_air::{DeserializationError, ExecutionProof, HashFunction, ProvingOptions, config};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, StackInputs, StackOutputs,
    SyncHost, Word, crypto, math, utils,
};
pub use miden_prover_p3::{Commitments, OpenedValues, Proof};
pub use public_inputs::{build_public_values, extract_public_values_from_trace};
pub use trace_adapter::{aux_trace_to_row_major, execution_trace_to_row_major};

// PROVER
// ================================================================================================

#[instrument("program proving", skip_all)]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError>
where
{
    // execute the program to create an execution trace
    let trace = {
        let _span = tracing::info_span!("execute_program").entered();
        miden_processor::execute(
            program,
            stack_inputs,
            advice_inputs,
            host,
            *options.execution_options(),
        )?
    };

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
    let public_values = extract_public_values_from_trace(&trace);

    // Create AIR with aux trace builders
    let air = ProcessorAir::with_aux_builder(trace.aux_trace_builders().clone());

    // Generate STARK proof using unified miden-prover
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_192 => {
            // TODO: Blake3_192 currently uses Blake3_256 config (32-byte output instead of
            // 24-byte). Proper 192-bit support requires Plonky3 to implement
            // CryptographicHasher<u8, [u8; 24]> for Blake3. Create an issue in
            // 0xMiden/Plonky3 to add this support.
            let config = miden_air::config::create_blake3_256_config();
            let proof = miden_prover_p3::prove(&config, &air, &trace_matrix, &public_values);
            bincode::serialize(&proof).expect("Failed to serialize proof")
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
