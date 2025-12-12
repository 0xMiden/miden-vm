//! Public inputs conversion utilities.
//!
//! This module provides functions to convert miden-vm's public inputs
//! (program info, stack inputs, stack outputs) into the format expected
//! by the miden-prover.

use alloc::vec::Vec;

use miden_air::{Felt, PublicInputs};
use miden_processor::{ProgramInfo, StackInputs, StackOutputs};

/// Builds the public values vector from program info and stack I/O.
///
/// The public values are encoded in a canonical order:
/// 1. Program info elements (program hash, kernel procedures, etc.)
/// 2. Stack inputs (up to 16 elements)
/// 3. Stack outputs (up to 16 elements)
///
/// This encoding must match the order expected by the AIR constraints
/// and the verifier.
///
/// # Arguments
///
/// * `program_info` - Information about the executed program
/// * `stack_inputs` - Initial stack values
/// * `stack_outputs` - Final stack values
///
/// # Returns
///
/// A vector of field elements representing the public inputs in canonical order.
pub fn build_public_values(
    program_info: &ProgramInfo,
    stack_inputs: &StackInputs,
    stack_outputs: &StackOutputs,
) -> Vec<Felt> {
    let public_inputs = PublicInputs::new(program_info.clone(), *stack_inputs, *stack_outputs);

    public_inputs.to_elements()
}

/// Extracts public values from an execution trace.
///
/// This is a convenience function that extracts the public inputs
/// directly from trace metadata.
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

    build_public_values(&program_info, &stack_inputs, &stack_outputs)
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for public input conversion
    // - Test encoding order
    // - Test with various stack sizes
    // - Verify consistency with AIR expectations
}
