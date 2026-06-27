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
    FutureMaybeSend, Host, Kernel, Program, ProgramInfo, StackInputs, SyncHost, TraceBuildInputs,
    TraceGenerationContext, ZERO, advice, crypto, execute, field, operation::Operation, serde,
    trace, trace::ExecutionTrace, utils,
};
#[cfg(not(target_family = "wasm"))]
pub use miden_prover::prove_from_trace_sync;
pub use miden_prover::{InputError, ProvingOptions, StackOutputs, TraceProvingInputs, Word};
pub use miden_verifier::VerificationError;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Executes and proves a Miden program with the built-in precompile registry.
pub async fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: advice::AdviceInputs,
    host: &mut impl Host,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    miden_prover::prove(
        program,
        stack_inputs,
        advice_inputs,
        host,
        execution_options,
        proving_options,
    )
    .await
}

/// Synchronous wrapper for [`prove`].
#[cfg(not(target_family = "wasm"))]
pub fn prove_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: advice::AdviceInputs,
    host: &mut impl SyncHost,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    miden_prover::prove_sync(
        program,
        stack_inputs,
        advice_inputs,
        host,
        execution_options,
        proving_options,
    )
}

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
