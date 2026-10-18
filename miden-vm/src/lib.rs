#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

// EXPORTS
// ================================================================================================

#[cfg(feature = "execution")]
pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_core::{
    deferred::{IntegrityError, PrecompileWitnessEntry},
    program::ExecutionClaim,
    proof::{
        ExecutionProof, ExecutionProofCompatibility, ExecutionProofCompatibilityError,
        ExecutionProofError, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof,
    },
};
#[cfg(feature = "execution")]
pub use miden_core_lib::conjectured_security_estimator_root;
#[cfg(feature = "execution")]
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FastProcessor, FutureMaybeSend, Host, PrecompileWitness, Program, ProgramExecutor, SyncHost,
    VmWitness, ZERO, advice, crypto, field, operation::Operation, serde, trace, trace::VmTrace,
    utils,
};
pub mod proofs;
pub use miden_core::{
    Word,
    advice::AdviceInputs,
    program::{KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
};
#[cfg(feature = "execution")]
pub use miden_processor::InputError;
pub use proofs::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm, StarkVerificationError, VerificationError, VerificationOutcome, Verifier,
};
#[cfg(feature = "prover")]
pub use proofs::{Prover, ProverError, prove_sync};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;

/// Compatibility forwarding for VM recursive advice.
#[cfg(feature = "recursive")]
pub use miden_vm_stark::recursive;
