//! Public inputs conversion utilities.
//!
//! This module provides functions to convert miden-vm's public inputs
//! (program info, stack inputs, stack outputs, precompile transcript state)
//! into the format expected by the Plonky3-based prover.
//!
//! # Why this module exists
//!
//! Plonky3's prover API expects public inputs as a flat `&[Felt]` vector, whereas
//! Winterfell's trait-based `Prover` handled public inputs internally through the AIR's
//! `get_pub_inputs()` method. This module bridges that gap by converting our high-level
//! `PublicInputs` struct into the flat vector format that `miden_prover_p3::prove()` expects.

use alloc::vec::Vec;

use miden_air::{Felt, PublicInputs};
use miden_processor::{PrecompileTranscriptState, ProgramInfo, StackInputs, StackOutputs};

/// Builds the public values vector from program info, stack I/O, and precompile transcript state.
///
/// The public values are encoded in a canonical order:
/// 1. Program info elements (program hash, kernel procedures, etc.)
/// 2. Stack inputs (up to 16 elements)
/// 3. Stack outputs (up to 16 elements)
/// 4. Precompile transcript state (4 elements)
///
/// This encoding must match the order expected by the AIR constraints
/// and the verifier.
///
/// # Arguments
///
/// * `program_info` - Information about the executed program
/// * `stack_inputs` - Initial stack values
/// * `stack_outputs` - Final stack values
/// * `pc_transcript_state` - Precompile transcript state
///
/// # Returns
///
/// A vector of field elements representing the public inputs in canonical order.
pub fn build_public_values(
    program_info: &ProgramInfo,
    stack_inputs: &StackInputs,
    stack_outputs: &StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
) -> Vec<Felt> {
    let public_inputs =
        PublicInputs::new(program_info.clone(), *stack_inputs, *stack_outputs, pc_transcript_state);

    public_inputs.to_elements()
}

/// Extracts public values from an execution trace.
///
/// This is a convenience function that extracts the public inputs
/// directly from trace metadata, including the precompile transcript state.
///
/// # Arguments
///
/// * `trace` - The execution trace containing program and stack information
///
/// # Returns
///
/// A vector of field elements representing the public inputs.
pub fn extract_public_values_from_trace(trace: &miden_processor::ExecutionTrace) -> Vec<Felt> {
    let stack_inputs = trace.init_stack_state();
    let stack_outputs = *trace.stack_outputs();
    let program_info = trace.program_info().clone();
    let pc_transcript_state = trace.final_precompile_transcript().state();

    build_public_values(&program_info, &stack_inputs, &stack_outputs, pc_transcript_state)
}
