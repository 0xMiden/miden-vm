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
/// Low-level processor state, execution modes, and session interfaces.
///
/// Use [`Processor`] to configure and run a program, or this namespace
/// to access lower-level machine controls.
pub use miden_processor as processor;
pub use miden_processor::{
    BaseHost, DefaultHost, Execute, ExecutionError, ExecutionOptions, ExecutionOutput,
    ExecutionPlan, ExecutionSession, ExecutionWitness, FutureMaybeSend, HaltedExecution, Host,
    Memory, PackageSourceDebugContext, Processor, RecordWitness, StepStatus, SyncHost,
    WitnessOutput, advice, crypto, field, serde, trace, utils,
};
pub use miden_prover::{PrecompileProvingError, Prover, ProverError};
pub use miden_verifier::{
    PrecompileVerificationError, ProofSecurityParameters, ProvenSecurityReport, SecurityReport,
    StarkVerificationError, VerificationError, VerificationOutcome, Verifier,
};
pub use miden_vm_stark::memory as trace_memory;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
