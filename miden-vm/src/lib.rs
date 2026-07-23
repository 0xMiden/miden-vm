#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_core::{
    program::ExecutionClaim,
    proof::{ExecutionProof, HashFunction},
};
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
pub use miden_verifier::{Unsettled, VerificationError, settle, verify_unsettled};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Verifies a fully settled Miden proof of the given execution claim.
///
/// See [miden_verifier::verify] for more details.
pub fn verify(proof: ExecutionProof, claim: ExecutionClaim) -> Result<u32, VerificationError> {
    miden_verifier::verify(proof, claim)
}
