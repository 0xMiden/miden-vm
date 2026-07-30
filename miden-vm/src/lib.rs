#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_core::proof::{DeferredProof, ExecutionProof, HashFunction, StarkProof};
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
pub use miden_verifier::{VerificationError, Verifier};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Verifies a final Miden proof.
///
/// Wire-backed deferred proofs are partial/delegable proof material and are rejected by this
/// verifier. Use [`Verifier::verify_partial`] to verify and hydrate wire-backed partial proofs.
///
/// Deprecated compatibility shim for [`Verifier::verify`].
#[deprecated(since = "0.25.0", note = "use Verifier::new().verify(...) instead")]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    Verifier::new().verify(program_info, stack_inputs, stack_outputs, proof)
}
