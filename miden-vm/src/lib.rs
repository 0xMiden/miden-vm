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
    deferred::{IntegrityError, PrecompileWitnessEntry},
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
pub use miden_verifier::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm, VerificationError, VerificationOutcome, Verifier,
};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
