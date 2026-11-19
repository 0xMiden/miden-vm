#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod execution;

// EXPORTS
// ================================================================================================

pub use execution::{Processor, ProveComplete, ProveDeferred, ProvingOutput, ProvingRunError};
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
/// Use [`Processor`] for the high-level execution builder. This namespace exposes the
/// processor crate for callers that need direct machine control or reusable execution modes
/// and session machinery.
pub use miden_processor as processor;
pub use miden_processor::{
    BaseHost, CompletedExecution, DefaultHost, Execute, Execution, ExecutionError,
    ExecutionOptions, ExecutionOutput, ExecutionSession, ExecutionTrace, ExecutionWitness,
    FutureMaybeSend, Host, Memory, PackageSourceDebugContext, StepStatus, SyncHost, Trace,
    TraceOutput, VmTraceBudget, Witness, WitnessOutput, advice, crypto, field, serde, trace,
    trace::VmTrace, utils,
};
pub use miden_prover::{CompleteProof, PrecompileProvingError, Prover, ProverError};
pub use miden_verifier::{
    PrecompileVerificationError, ProofSecurityParameters, ProvenSecurityReport, SecurityReport,
    StarkVerificationError, VerificationError, VerificationOutcome, Verifier,
};
pub use miden_vm_stark::memory as trace_memory;

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
