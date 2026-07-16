#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_core::proof::{ExecutionProof, HashFunction};
#[cfg(not(target_family = "wasm"))]
pub use miden_processor::execute_sync;
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor,
    FutureMaybeSend, Host, KernelDescriptor, Program, ProgramInfo, StackInputs, SyncHost,
    TraceBuildInputs, TraceGenerationContext, ZERO, advice, crypto, execute, field,
    operation::Operation, serde, trace, trace::ExecutionTrace, utils,
};
pub use miden_prover::{InputError, ProvingOptions, StackOutputs, TraceProvingInputs, Word, prove};
#[cfg(not(target_family = "wasm"))]
pub use miden_prover::{prove_from_trace_sync, prove_sync};
pub use miden_verifier::VerificationError;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Verifies a Miden proof.
///
/// See [miden_verifier::verify] for more details.
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    miden_verifier::verify(program_info, stack_inputs, stack_outputs, proof)
}

/// Verifies a Miden proof using an explicit deferred-state verifier budget.
///
/// See [miden_verifier::verify_with_max_deferred_elements] for more details.
pub fn verify_with_max_deferred_elements(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
    max_deferred_elements: usize,
) -> Result<u32, VerificationError> {
    miden_verifier::verify_with_max_deferred_elements(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        max_deferred_elements,
    )
}
