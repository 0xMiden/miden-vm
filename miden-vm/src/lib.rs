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
/// Low-level processor type for callers that need direct execution control.
///
/// `FastProcessor` includes the built-in precompile registry by default.
pub use miden_processor::FastProcessor;
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FutureMaybeSend,
    Host, Kernel, Program, ProgramInfo, StackInputs, SyncHost, TraceBuildInputs,
    TraceGenerationContext, ZERO, advice, crypto, field, operation::Operation, serde, trace,
    trace::ExecutionTrace, utils,
};
#[cfg(not(target_family = "wasm"))]
pub use miden_prover::prove_from_trace_sync;
pub use miden_prover::{InputError, ProvingOptions, StackOutputs, TraceProvingInputs, Word};
pub use miden_verifier::VerificationError;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Executes the provided program.
///
/// The `host` parameter is used to provide the external environment to the program being executed,
/// such as access to the advice provider and libraries that the program depends on.
///
/// # Errors
/// Returns an error if program execution fails for any reason.
#[tracing::instrument("execute_program", skip_all)]
pub async fn execute(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: advice::AdviceInputs,
    host: &mut impl Host,
    options: ExecutionOptions,
) -> Result<ExecutionOutput, ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
        .map_err(ExecutionError::advice_error_no_context)?;

    processor.execute(program, host).await
}

/// Synchronous wrapper for [`execute`].
///
/// This method is only available on non-wasm32 targets. On wasm32, use the async [`execute`]
/// method directly since wasm32 runs in the browser's event loop.
///
/// # Panics
/// Panics if called from within an existing Tokio runtime. Use [`execute`] instead in async
/// contexts.
#[cfg(not(target_family = "wasm"))]
#[tracing::instrument("execute_program_sync", skip_all)]
pub fn execute_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: advice::AdviceInputs,
    host: &mut impl SyncHost,
    options: ExecutionOptions,
) -> Result<ExecutionOutput, ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
        .map_err(ExecutionError::advice_error_no_context)?;

    processor.execute_sync(program, host)
}

/// Executes and proves a Miden program.
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
