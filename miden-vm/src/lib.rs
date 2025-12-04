#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_processor::{
    AdviceInputs, AdviceProvider, AsmOpInfo, AsyncHost, BaseHost, DefaultHost, ExecutionError,
    ExecutionTrace, Kernel, Operation, Program, ProgramInfo, StackInputs, SyncHost, VmState,
    VmStateIterator, ZERO, crypto, execute, execute_iter, utils,
};
pub use miden_prover::{
    ExecutionProof, FieldExtension, HashFunction, InputError, Proof, ProvingOptions, StackOutputs,
    Word, math, prove,
};
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
    let registry = miden_libcore::CoreLibrary::default().verifier_registry();
    let (security_level, _) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &registry,
    )?;
    Ok(security_level)
}
