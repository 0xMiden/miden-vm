#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_core::{
    deferred::{DeferredStateWire, PrecompileWitnessError},
    program::ExecutionClaim,
    proof::{
        ExecutionProof, ExecutionProofCompatibility, ExecutionProofCompatibilityError,
        ExecutionProofError, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof,
    },
};
pub use miden_core_lib::conjectured_security_estimator_root;
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FastProcessor, FutureMaybeSend, Host, KernelDescriptor, PrecompileWitness, Program,
    ProgramExecutor, ProgramInfo, StackInputs, SyncHost, VmWitness, ZERO, advice, crypto, field,
    operation::Operation, serde, trace, trace::VmTrace, utils,
};
pub use miden_prover::{InputError, Prover, ProverError, StackOutputs, Word, prove_sync};
pub use miden_verifier::{VerificationError, VerificationOutcome, Verifier};

/// Hydrates a passive deferred-state wire using the standard bundled precompile registry.
///
/// This is the public factory for precompile witnesses produced outside local execution. It
/// validates the wire under the facade's installed precompiles before constructing the witness.
pub fn precompile_witness_from_wire(
    wire: &DeferredStateWire,
) -> Result<PrecompileWitness, PrecompileWitnessError> {
    let state = miden_core::deferred::DeferredState::from_wire(
        alloc::sync::Arc::new(miden_precompiles::registry()),
        wire,
    )?;
    PrecompileWitness::new(state)
}

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
