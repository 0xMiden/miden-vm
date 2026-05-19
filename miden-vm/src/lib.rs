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
pub use miden_prover::{InputError, ProvingOptions, StackOutputs, TraceProvingInputs, Word, prove};
#[cfg(not(target_family = "wasm"))]
pub use miden_prover::{prove_from_trace_sync, prove_sync};
pub use miden_verifier::VerificationError;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Verifies a Miden proof using the production `CoreLibrary` precompile schema.
///
/// This is **L3** of the layered verifier API — a default-schema convenience wrapper around
/// [`miden_verifier::verify`]. Programs that use the core library's precompile MASM wrappers
/// (keccak256, sha512, ecdsa_k256_keccak, eddsa_ed25519) are verified end-to-end through this
/// entry-point. For non-default schemas or callers that want the deferred commitment
/// separately, call `miden_verifier::verify` directly.
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    let schema = miden_core_lib::CoreLibrary::default().precompile_schema();
    let (security_level, _commitment) =
        miden_verifier::verify(program_info, stack_inputs, stack_outputs, &schema, proof)?;
    Ok(security_level)
}
