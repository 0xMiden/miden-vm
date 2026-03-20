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
#[cfg(not(target_arch = "wasm32"))]
pub use miden_processor::execute_sync;
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor,
    FutureMaybeSend, Host, Kernel, Program, ProgramInfo, StackInputs, SyncHost,
    TraceGenerationContext, ZERO, advice, crypto, execute, field, operation::Operation, serde,
    trace, trace::ExecutionTrace, utils,
};
pub use miden_prover::{InputError, ProvingOptions, StackOutputs, Word, prove};
#[cfg(not(target_arch = "wasm32"))]
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
    let registry = miden_core_lib::CoreLibrary::default().verifier_registry();
    let (security_level, _) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &registry,
    )?;
    Ok(security_level)
}
