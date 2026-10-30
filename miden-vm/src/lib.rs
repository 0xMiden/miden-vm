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
    Word, ZERO,
    deferred::{
        DeferredRoot, IntegrityError, PrecompileError, PrecompileLimits, PrecompileWitness,
        PrecompileWitnessEntry, PreparationError, WorkClass, WorkLimit,
    },
    operations::Operation,
    program::{
        ExecutionClaim, InputError, KernelDescriptor, Program, ProgramInfo, StackInputs,
        StackOutputs,
    },
    proof::{
        ExecutionProof, ExecutionProofCompatibility, ExecutionProofCompatibilityError,
        ExecutionProofError, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof,
    },
};
pub use miden_core_lib::{conjectured_security_estimator_root, proven_security_estimator_root};
pub use miden_precompiles::{
    CURVE_WORK, HASH_WORK, MSM_WORK, UINT_WORK, default_execution_precompile_limits,
    default_verification_precompile_limits,
};
pub use miden_processor::{
    BaseHost, DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FastProcessor, FutureMaybeSend, Host, ProgramExecutor, SyncHost, VmWitness, advice, crypto,
    field, serde, trace, trace::VmTrace, utils,
};
pub use miden_prover::{PrecompileProvingError, Prover, ProverError, prove_sync};
pub use miden_verifier::{
    PrecompileVerificationError, ProofSecurityParameters, ProvenSecurityReport, SecurityReport,
    StarkVerificationError, VerificationError, VerificationOutcome, Verifier,
};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
